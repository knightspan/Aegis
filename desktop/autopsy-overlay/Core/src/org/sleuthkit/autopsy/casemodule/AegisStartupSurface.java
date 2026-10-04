/*
 * AEGIS Forensic Platform
 *
 * Lookup contract so Core can open the AEGIS home surface without a
 * compile-time dependency on the AEGIS module.
 */
package org.sleuthkit.autopsy.casemodule;

/**
 * Implemented by the AEGIS module and discovered through NetBeans Lookup.
 */
public interface AegisStartupSurface {

    /**
     * Makes the AEGIS home workspace the first visible product surface.
     */
    void showAegisHome();
}
