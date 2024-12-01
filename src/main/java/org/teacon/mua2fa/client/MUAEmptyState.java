package org.teacon.mua2fa.client;

import com.mojang.serialization.Codec;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.util.StringRepresentable;

import javax.annotation.ParametersAreNonnullByDefault;
import java.util.Locale;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public enum MUAEmptyState implements StringRepresentable {
    INIT, SHOW_IF_NECESSARY, HIDE_FOREVER;

    public static final Codec<MUAEmptyState> CODEC = StringRepresentable.fromEnum(MUAEmptyState::values);

    @Override
    public String getSerializedName() {
        return this.name().toLowerCase(Locale.ROOT);
    }
}
