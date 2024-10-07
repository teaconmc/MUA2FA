package org.teacon.mua2fa;

import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.neoforged.fml.common.Mod;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.ParametersAreNonnullByDefault;

@Mod(MUA2FA.ID)
@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class MUA2FA {
    public static final String ID = "mua2fa";
    public static final String NETWORK_VERSION = "1";
    public static final String MUA_HOST = "skin.mualliance.ltd";
    public static final Logger LOGGER = LogManager.getLogger("MUA2FA");
}
