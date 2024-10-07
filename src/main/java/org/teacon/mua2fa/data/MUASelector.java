package org.teacon.mua2fa.data;

import com.google.common.base.Predicates;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.commands.arguments.selector.EntitySelectorParser;
import net.minecraft.commands.arguments.selector.options.EntitySelectorOptions;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import javax.annotation.ParametersAreNonnullByDefault;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class MUASelector {
    public static final String ID = "mua";
    private static final Component TOOLTIP = Component.translatable("argument.entity.options.mua2fa.mua.description");

    private MUASelector() {
        throw new UnsupportedOperationException();
    }

    public static void register(BiPredicate<Matcher, ServerPlayer> filter) {
        EntitySelectorOptions.register(ID, parser -> handle(parser, filter), Predicates.alwaysTrue(), TOOLTIP);
    }

    private static void handle(EntitySelectorParser parser, BiPredicate<Matcher, ServerPlayer> filter) {
        var reader = parser.getReader();
        var inv = parser.shouldInvertValue();
        if (reader.canRead() && reader.peek() == '*') {
            reader.skip();
            if (reader.canRead(2) && reader.peek() == ':' && reader.peek(1) == '*') {
                reader.skip();
                reader.skip();
            }
            parser.addPredicate(e -> e instanceof ServerPlayer p && inv != filter.test(Everything.INSTANCE, p));
            return;
        }
        var c = reader.readUnquotedString();
        if (reader.canRead() && reader.peek() == ':') {
            reader.skip();
            if (reader.canRead() && reader.peek() == '*') {
                reader.skip();
                parser.addPredicate(e -> e instanceof ServerPlayer p && inv != filter.test(new Prefix(c + ":"), p));
                return;
            }
            var s = reader.readUnquotedString();
            parser.addPredicate(e -> e instanceof ServerPlayer p && inv != filter.test(new Exact(c + ":" + s), p));
            return;
        }
        parser.addPredicate(e -> e instanceof ServerPlayer p && inv != filter.test(new Exact(c), p));
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public sealed interface Matcher extends Predicate<String> permits Everything, Prefix, Exact {
        // nothing here
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public record Prefix(String prefix) implements Matcher {
        @Override
        public boolean test(String sub) {
            return sub.startsWith(this.prefix);
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public record Exact(String sub) implements Matcher {
        @Override
        public boolean test(String sub) {
            return sub.equals(this.sub);
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public enum Everything implements Matcher {
        INSTANCE;

        @Override
        public boolean test(String sub) {
            return true;
        }
    }
}
