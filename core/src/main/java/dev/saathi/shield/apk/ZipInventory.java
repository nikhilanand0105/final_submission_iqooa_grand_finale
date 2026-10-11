package dev.saathi.shield.apk;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Counts of archive entries by kind, plus structural anomalies observed while listing them. */
public final class ZipInventory {

    public final int totalEntries;
    public final int dexFiles;
    public final int nativeLibs;
    public final int assets;
    public final int resources;
    public final int metaInf;
    public final long declaredUncompressedBytes;
    public final Set<String> abis;
    public final List<String> anomalies;

    ZipInventory(int totalEntries, int dexFiles, int nativeLibs, int assets, int resources, int metaInf,
                 long declaredUncompressedBytes, Set<String> abis, List<String> anomalies) {
        this.totalEntries = totalEntries;
        this.dexFiles = dexFiles;
        this.nativeLibs = nativeLibs;
        this.assets = assets;
        this.resources = resources;
        this.metaInf = metaInf;
        this.declaredUncompressedBytes = declaredUncompressedBytes;
        this.abis = Collections.unmodifiableSet(abis);
        this.anomalies = Collections.unmodifiableList(anomalies);
    }
}
