package org.teacon.mua2fa.data;

import com.google.common.base.Preconditions;
import com.google.common.hash.HashCode;
import com.mojang.serialization.Codec;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.EncoderException;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.codec.StreamCodec;

import javax.annotation.ParametersAreNonnullByDefault;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class HashBase85 {
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!#$%&()*+-;<=>?@^_`{|}~";
    private static final String UPPER_CASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER_CASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
    private static final String ALPHABET = NUMBERS + UPPER_CASE_LETTERS + LOWER_CASE_LETTERS + SYMBOLS;

    private HashBase85() {
        throw new UnsupportedOperationException();
    }

    public static final Codec<HashCode> CODEC = Codec.STRING.xmap(HashBase85::decode, HashBase85::encode);

    public static String encode(HashCode hash) {
        if (hash.bits() % 32 != 0) {
            throw new EncoderException("only hash codes whose bit count is an integer multiple of 32 bits allowed");
        }
        var buffer = ByteBuffer.wrap(hash.asBytes()).order(ByteOrder.BIG_ENDIAN);
        var builder = new StringBuilder(hash.bits() / 32 * 5);
        while (buffer.hasRemaining()) {
            var value = buffer.getInt();
            builder.append(ALPHABET.charAt(Integer.divideUnsigned(value, 85 * 85 * 85 * 85) % 85));
            builder.append(ALPHABET.charAt(Integer.divideUnsigned(value, 85 * 85 * 85) % 85));
            builder.append(ALPHABET.charAt(Integer.divideUnsigned(value, 85 * 85) % 85));
            builder.append(ALPHABET.charAt(Integer.divideUnsigned(value, 85) % 85));
            builder.append(ALPHABET.charAt(Integer.remainderUnsigned(value, 85)));
        }
        return builder.toString();
    }

    public static HashCode decode(String hash) {
        var hashLength = hash.length();
        if (Math.max(hashLength / 5, 1) * 5 != hashLength) {
            throw new DecoderException("only hash strings whose size is a positive integer multiple of 5 allowed");
        }
        var buffer = ByteBuffer.allocate(hashLength / 5 * 4).order(ByteOrder.BIG_ENDIAN);
        for (var i = 0; i < hashLength; i += 5) {
            // noinspection ExtractMethodRecommender
            var i0 = ALPHABET.indexOf(hash.charAt(i));
            var i1 = ALPHABET.indexOf(hash.charAt(i + 1));
            var i2 = ALPHABET.indexOf(hash.charAt(i + 2));
            var i3 = ALPHABET.indexOf(hash.charAt(i + 3));
            var i4 = ALPHABET.indexOf(hash.charAt(i + 4));
            if ((i0 | i1 | i2 | i3 | i4) < 0) {
                throw new DecoderException("invalid character at index range [" + i + ", " + (i + 4) + "]");
            }
            var value = (((i0 * 85L + i1) * 85L + i2) * 85L + i3) * 85L + i4;
            if (value >= 1L << 32) {
                throw new DecoderException("invalid character at index range [" + i + ", " + (i + 4) + "]");
            }
            buffer.putInt((int) value);
        }
        return HashCode.fromBytes(buffer.array());
    }

    public static StreamCodec<ByteBuf, HashCode> ofStreamCodec(int fixBits) {
        Preconditions.checkArgument(fixBits % 32 == 0);
        return StreamCodec.of((buf, digest) -> {
            if (digest.bits() != fixBits) {
                throw new EncoderException("unexpected hash bits: " + digest.bits() + " != " + fixBits);
            }
            buf.writeBytes(digest.asBytes(), 0, fixBits / 8);
        }, buf -> {
            var bytes = new byte[fixBits / 8];
            buf.readBytes(bytes, 0, fixBits / 8);
            return HashCode.fromBytes(bytes);
        });
    }
}
