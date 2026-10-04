/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2017 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.casemodule;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JDialog;
import org.openide.util.Lookup;
import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.openide.windows.WindowManager;

/**
 * Retained as the Component parent for existing case file choosers.
 * It is no longer the default user-facing startup surface.
 */
@ServiceProvider(service = StartupWindowInterface.class)
public final class StartupWindow extends JDialog implements StartupWindowInterface {

    private static final long serialVersionUID = 1L;
    private static final String TITLE = NbBundle.getMessage(StartupWindow.class, "StartupWindow.title.text");
    private static final Dimension DIMENSIONS = new Dimension(750, 400);
    private static CueBannerPanel welcomeWindow;

    public StartupWindow() {
        super(WindowManager.getDefault().getMainWindow(), TITLE, true);
        init();
    }

    private void init() {
        setSize(DIMENSIONS);
        setResizable(false);
    }

    /**
     * Builds the legacy Welcome panel. Kept for internal case flows that
     * still need this dialog. Not used as the default startup path.
     */
    void openLegacyWelcome() {
        if (welcomeWindow == null) {
            welcomeWindow = new CueBannerPanel();
            welcomeWindow.setCloseButtonActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    close();
                }
            });
            add(welcomeWindow);
            pack();
        }
        setVisible(true);
    }

    @Override
    public void open() {
        AegisStartupSurface surface = Lookup.getDefault().lookup(AegisStartupSurface.class);
        if (surface != null) {
            surface.showAegisHome();
            return;
        }
        try {
            ClassLoader loader = Lookup.getDefault().lookup(ClassLoader.class);
            Class<?> shell = Class.forName("org.sleuthkit.autopsy.aegis.ui.AegisShell", true,
                    loader != null ? loader : Thread.currentThread().getContextClassLoader());
            shell.getMethod("install").invoke(null);
            shell.getMethod("showHome").invoke(null);
        } catch (Exception ignore) {
            WindowManager.getDefault().invokeWhenUIReady(() -> {
                AegisStartupSurface retry = Lookup.getDefault().lookup(AegisStartupSurface.class);
                if (retry != null) {
                    retry.showAegisHome();
                }
            });
        }
    }

    @Override
    public void close() {
        this.setVisible(false);
    }
}
