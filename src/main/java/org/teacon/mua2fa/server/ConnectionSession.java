package org.teacon.mua2fa.server;

import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;

import javax.annotation.ParametersAreNonnullByDefault;
import java.time.Instant;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record ConnectionSession(Instant deadline, ServerConfigurationPacketListenerImpl conn) {
    // nothing here
}
