package org.teacon.mua2fa.data;

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.gson.JsonObject;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import com.mojang.authlib.GameProfile;
import com.mojang.datafixers.util.Either;
import com.mojang.datafixers.util.Pair;
import com.mojang.serialization.Codec;
import com.mojang.serialization.DataResult;
import com.mojang.serialization.JsonOps;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.codec.http.QueryStringEncoder;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.Util;
import net.minecraft.util.GsonHelper;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.server.ConfigSpec;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.netty.ByteBufFlux;
import reactor.netty.ByteBufMono;
import reactor.netty.DisposableServer;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientResponse;
import reactor.netty.http.server.HttpServer;

import javax.annotation.ParametersAreNonnullByDefault;
import java.io.Closeable;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReference;

import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_JSON;
import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED;
import static net.minecraft.server.network.ServerConnectionListener.SERVER_EPOLL_EVENT_GROUP;
import static net.minecraft.server.network.ServerConnectionListener.SERVER_EVENT_GROUP;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class OAuthHttp implements Closeable {
    public static final Duration POLL_INTERVAL = Duration.ofSeconds(5L);
    public static final Duration NETWORK_TOLERANCE = Duration.ofSeconds(30L);
    public static final Duration MUA_REQUEST_COUNTDOWN = Duration.ofSeconds(180L);

    private static final Marker MARKER = MarkerManager.getMarker("OAuth");

    private static final String STARTING = "Starting oauth http server ...";
    private static final String STARTED = "Started oauth http server at {}.";
    private static final String STOPPING = "Stopping oauth http server at {} ...";
    private static final String STOPPED = "Stopped oauth http server.";
    private static final String HTML = """
            <!doctype html><html><head><meta charset="utf-8"><meta name="viewport"
            content="width=device-width,initial-scale=1"><title>MUA2FA</title></head>
            <body><pre style="height:88vh;font-size:4vh;display:flex;align-items:center;
            justify-content:center;text-align:center;color:%s">%s</pre></body></html>""";

    private static final Scheduler IO_SCHEDULER = Schedulers.fromExecutor(Util.ioPool());

    private static final Codec<MUARecord> RECORD_CODEC = MUARecord.MAP_CODEC.codec();

    private final AtomicReference<DisposableServer> server = new AtomicReference<>();
    private final Sinks.Many<MUARecord.User> records = Sinks.many().replay().limit(NETWORK_TOLERANCE, IO_SCHEDULER);

    private static Mono<JsonObject> json(HttpClientResponse res, ByteBufMono body) {
        return body.asString().flatMap(content -> Mono.fromCallable(() -> {
            Preconditions.checkArgument(res.status().code() == 200);
            try (var reader = new JsonReader(new StringReader(content))) {
                return Streams.parse(reader).getAsJsonObject();
            }
        }));
    }

    private static Either<OAuthState, Exception> state(Map<String, List<String>> params) {
        try {
            var stateStr = Iterables.getOnlyElement(params.getOrDefault("state", List.of()));
            return Either.left(OAuthState.fromString(stateStr));
        } catch (IllegalArgumentException | NoSuchElementException e) {
            return Either.right(e);
        }
    }

    private static Either<String, Exception> code(Map<String, List<String>> params) {
        try {
            return Either.left(Iterables.getOnlyElement(params.getOrDefault("code", List.of())));
        } catch (IllegalArgumentException | NoSuchElementException e) {
            return Either.right(e);
        }
    }

    public static URI auth(ConfigSpec conf) {
        var relative = FilenameUtils.getName(conf.getServerExternalUri().getPath());
        return conf.getServerExternalUri().resolve(StringUtils.defaultIfEmpty(relative, ".") + "/redirect");
    }

    public static URI record(ConfigSpec conf) {
        var relative = FilenameUtils.getName(conf.getServerExternalUri().getPath());
        return conf.getServerExternalUri().resolve(StringUtils.defaultIfEmpty(relative, ".") + "/record");
    }

    public static Mono<MUARecord> poll(URI recordUri, String ua, Duration interval) {
        var client = HttpClient.create().headers(headers -> {
            headers.add(HttpHeaderNames.ACCEPT, APPLICATION_JSON);
            headers.add(HttpHeaderNames.USER_AGENT, ua);
        });
        var single = client.get().uri(recordUri.toString()).responseSingle((res, mono) -> {
            var json = mono.asString(StandardCharsets.UTF_8).map(GsonHelper::parse);
            var result = json.map(o -> RECORD_CODEC.decode(JsonOps.INSTANCE, o));
            return result.map(DataResult::getOrThrow).map(Pair::getFirst);
        });
        return Mono.zip(Mono.delay(interval), single, (a, b) -> b).retry();
    }

    public void start(boolean epoll, ConfigSpec conf, String ua) {
        var addr = conf.getServerInternalAddress();
        var runOn = epoll ? SERVER_EPOLL_EVENT_GROUP.get() : SERVER_EVENT_GROUP.get();
        var server = HttpServer.create().runOn(runOn).host(addr.getHost()).port(addr.getPort()).route(routes -> {
            routes.get("/record", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var stateEither = state(dec.parameters());
                var users = stateEither.swap().<Flux<String>>map(Flux::error, state -> {
                    var now = OffsetDateTime.now();
                    var key = conf.getTokenSignKey();
                    var verified = state.verify(key.getFirst()).test(now.toInstant());
                    if (!verified) {
                        return Flux.error(new IllegalArgumentException("invalid signature for state: " + state));
                    }
                    var expire = now.plus(conf.getTokenValidityPeriod());
                    var profile = new GameProfile(state.id(), state.name());
                    return this.records.asFlux().take(POLL_INTERVAL).flatMap(user -> Mono.fromCallable(() -> {
                        var record = user.sign(profile, expire.toInstant(), key);
                        var result = RECORD_CODEC.encodeStart(JsonOps.INSTANCE, record);
                        return GsonHelper.toStableString(result.getOrThrow());
                    }));
                });
                var name = stateEither.map(OAuthState::name, e -> "???");
                return users.next().switchIfEmpty(Mono.defer(() -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, APPLICATION_JSON);
                    MUA2FA.LOGGER.info(MARKER, "No suitable record found for player {}, replying ...", name);
                    return header.status(404).sendString(Mono.just("{\"error\":\"not found\"}")).then();
                }).then(Mono.empty())).flatMap(s -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, APPLICATION_JSON);
                    MUA2FA.LOGGER.info(MARKER, "Giving the signed record for player {} ...", name);
                    return header.sendString(Mono.just(s)).then();
                }).onErrorResume(e -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, APPLICATION_JSON);
                    MUA2FA.LOGGER.info(MARKER, "Error thrown when signing a record for player {}, replying ...", name);
                    MUA2FA.LOGGER.debug(MARKER, "Error thrown on processing: {}", e.getMessage(), e);
                    return header.status(400).sendString(Mono.just("{\"error\":\"bad request\"}")).then();
                });
            });
            routes.get("/redirect", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var stateEither = state(dec.parameters());
                var enc = new QueryStringEncoder("/api/union/oauth2/authorize");
                enc.addParam("response_type", "code");
                enc.addParam("client_id", conf.getMUAUnionAuthClientId());
                enc.addParam("redirect_uri", conf.getServerExternalUri().toString());
                stateEither.ifLeft(state -> enc.addParam("state", state.toString()));
                var name = stateEither.map(OAuthState::name, e -> "???");
                MUA2FA.LOGGER.info(MARKER, "Redirecting player {} to mua union auth page ...", name);
                return res.sendRedirect("https://" + MUA2FA.MUA_HOST + enc);
            });
            routes.get("/", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var stateEither = state(dec.parameters());
                var codeEither = code(dec.parameters());
                var enc = new QueryStringEncoder("/");
                enc.addParam("grant_type", "authorization_code");
                codeEither.ifLeft(code -> enc.addParam("code", code));
                enc.addParam("client_id", conf.getMUAUnionAuthClientId());
                enc.addParam("client_secret", conf.getMUAUnionAuthClientSecret());
                enc.addParam("redirect_uri", conf.getServerExternalUri().toString());
                var name = stateEither.map(OAuthState::name, e -> "???");
                var tokenRes = stateEither.swap().<Mono<JsonObject>>map(Mono::error, state -> {
                    var now = OffsetDateTime.now();
                    var key = conf.getTokenSignKey();
                    var verified = state.verify(key.getFirst()).test(now.toInstant());
                    if (!verified) {
                        return Mono.error(new IllegalArgumentException("invalid signature for state: " + state));
                    }
                    MUA2FA.LOGGER.info(MARKER, "Requesting the authorization token for player {} ...", name);
                    var tokenClient = HttpClient.create().runOn(runOn).headers(headers -> {
                        headers.add(HttpHeaderNames.CONTENT_TYPE, APPLICATION_X_WWW_FORM_URLENCODED);
                        headers.add(HttpHeaderNames.ACCEPT, APPLICATION_JSON);
                        headers.add(HttpHeaderNames.USER_AGENT, ua);
                    });
                    var tokenUri = "https://" + MUA2FA.MUA_HOST + "/api/union/oauth2/token";
                    var tokenBody = ByteBufFlux.fromString(Mono.fromCallable(() -> enc.toUri().getQuery()));
                    return tokenClient.post().uri(tokenUri).send(tokenBody).responseSingle(OAuthHttp::json);
                });
                var tokenStr = tokenRes.flatMap(json -> Mono.fromCallable(() -> {
                    var token = json.get("access_token").getAsString();
                    var tokenType = json.get("token_type").getAsString();
                    Preconditions.checkArgument("bearer".equalsIgnoreCase(tokenType));
                    return tokenType + " " + token;
                }));
                var userRes = tokenStr.flatMap(str -> {
                    MUA2FA.LOGGER.info(MARKER, "Requesting the user information for player {} ...", name);
                    var userClient = HttpClient.create().runOn(runOn).headers(headers -> {
                        headers.add(HttpHeaderNames.ACCEPT, APPLICATION_JSON);
                        headers.add(HttpHeaderNames.AUTHORIZATION, str);
                        headers.add(HttpHeaderNames.USER_AGENT, ua);
                    });
                    var userUri = "https://" + MUA2FA.MUA_HOST + "/api/union/oauth2/user";
                    return userClient.get().uri(userUri).responseSingle(OAuthHttp::json);
                });
                var userObj = userRes.flatMap(json -> Mono.fromCallable(() -> {
                    var result = MUARecord.User.CODEC.decode(JsonOps.INSTANCE, json);
                    return result.getOrThrow().getFirst();
                }));
                return Mono.zip(userObj, stateEither.map(Mono::just, Mono::error), Pair::of).flatMap(pair -> {
                    MUA2FA.LOGGER.info(MARKER, "Finished the oauth process of player {}, replying ...", name);
                    var hint = pair.getSecond().completeHint();
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                    this.records.emitNext(pair.getFirst(), Sinks.EmitFailureHandler.FAIL_FAST);
                    return header.sendString(Mono.just(String.format(HTML, "#066805", hint))).then();
                }).onErrorResume(e -> {
                    MUA2FA.LOGGER.info(MARKER, "Error thrown of the oauth process for player {}, replying ...", name);
                    return stateEither.map(s -> {
                        var hint = s.cancelHint();
                        var header = res.header(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                        MUA2FA.LOGGER.warn(MARKER, "Error thrown on processing (state: {}): {}", s, e.getMessage(), e);
                        return header.status(400).sendString(Mono.just(String.format(HTML, "#97242c", hint))).then();
                    }, ignored -> {
                        var hint = "Bad Request";
                        var header = res.header(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                        MUA2FA.LOGGER.warn(MARKER, "Error thrown on processing (state: ???): {}", e.getMessage(), e);
                        return header.status(400).sendString(Mono.just(String.format(HTML, "#97242c", hint))).then();
                    });
                });
            });
        });
        MUA2FA.LOGGER.info(MARKER, STARTING);
        this.server.set(server.doOnBound(s -> MUA2FA.LOGGER.info(MARKER, STARTED, s.address())).bindNow());
    }

    @Override
    public void close() {
        var server = this.server.getAndSet(null);
        if (server != null) {
            MUA2FA.LOGGER.info(MARKER, STOPPING, server.address());
            server.onDispose().doAfterTerminate(() -> MUA2FA.LOGGER.info(MARKER, STOPPED)).subscribe();
        }
    }
}
