package org.sleuthkit.autopsy.aegis.ui;

import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;
import org.sleuthkit.autopsy.casemodule.AegisStartupSurface;
import org.sleuthkit.autopsy.casemodule.StartupWindowInterface;

/**
 * AEGIS Lookup services for startup. Core opens this through AegisStartupSurface.
 */
@ServiceProviders({
    @ServiceProvider(service = AegisStartupSurface.class),
    @ServiceProvider(service = StartupWindowInterface.class)
})
public final class AegisStartupWindow implements StartupWindowInterface, AegisStartupSurface {

    @Override
    public void open() {
        showAegisHome();
    }

    @Override
    public void showAegisHome() {
        AegisShell.install();
        AegisShell.showHome();
    }

    @Override
    public void close() {
        // The dashboard stays visible. There is no Autopsy Welcome dialog to hide.
    }
}
