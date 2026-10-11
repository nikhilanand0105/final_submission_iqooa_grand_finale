package dev.guardianai.model;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Bytecode characteristics discovered across classes*.dex.
 */
public class DexInspectionResult {
    private final int dexFileCount;
    private final int totalClassCount;
    private final int totalMethodCount;
    private final Set<String> suspiciousApiReferences;
    private final List<String> extractedUrls;
    private final List<String> extractedIps;
    private final boolean usesDynamicCodeLoading; // DexClassLoader, InMemoryDexClassLoader
    private final boolean usesReflection;          // Method.invoke
    private final boolean executesShellCommands;   // Runtime.exec, ProcessBuilder
    private final boolean loadsNativeLibraries;    // System.loadLibrary
    private final boolean hasRootCheckStrings;     // /system/bin/su, Magisk
    private final boolean hasAccessibilityServiceAbuseStrings;

    public DexInspectionResult(
            int dexFileCount,
            int totalClassCount,
            int totalMethodCount,
            Set<String> suspiciousApiReferences,
            List<String> extractedUrls,
            List<String> extractedIps,
            boolean usesDynamicCodeLoading,
            boolean usesReflection,
            boolean executesShellCommands,
            boolean loadsNativeLibraries,
            boolean hasRootCheckStrings,
            boolean hasAccessibilityServiceAbuseStrings) {
        this.dexFileCount = dexFileCount;
        this.totalClassCount = totalClassCount;
        this.totalMethodCount = totalMethodCount;
        this.suspiciousApiReferences = suspiciousApiReferences != null ? suspiciousApiReferences : Collections.emptySet();
        this.extractedUrls = extractedUrls != null ? extractedUrls : Collections.emptyList();
        this.extractedIps = extractedIps != null ? extractedIps : Collections.emptyList();
        this.usesDynamicCodeLoading = usesDynamicCodeLoading;
        this.usesReflection = usesReflection;
        this.executesShellCommands = executesShellCommands;
        this.loadsNativeLibraries = loadsNativeLibraries;
        this.hasRootCheckStrings = hasRootCheckStrings;
        this.hasAccessibilityServiceAbuseStrings = hasAccessibilityServiceAbuseStrings;
    }

    public int getDexFileCount() {
        return dexFileCount;
    }

    public int getTotalClassCount() {
        return totalClassCount;
    }

    public int getTotalMethodCount() {
        return totalMethodCount;
    }

    public Set<String> getSuspiciousApiReferences() {
        return suspiciousApiReferences;
    }

    public List<String> getExtractedUrls() {
        return extractedUrls;
    }

    public List<String> getExtractedIps() {
        return extractedIps;
    }

    public boolean usesDynamicCodeLoading() {
        return usesDynamicCodeLoading;
    }

    public boolean usesReflection() {
        return usesReflection;
    }

    public boolean executesShellCommands() {
        return executesShellCommands;
    }

    public boolean loadsNativeLibraries() {
        return loadsNativeLibraries;
    }

    public boolean hasRootCheckStrings() {
        return hasRootCheckStrings;
    }

    public boolean hasAccessibilityServiceAbuseStrings() {
        return hasAccessibilityServiceAbuseStrings;
    }
}
