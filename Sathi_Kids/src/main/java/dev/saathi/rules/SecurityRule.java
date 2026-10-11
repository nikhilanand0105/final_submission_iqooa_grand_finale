package dev.saathi.rules;

import dev.saathi.model.CertificateMetadata;
import dev.saathi.model.DexInspectionResult;
import dev.saathi.model.ManifestMetadata;
import dev.saathi.model.ThreatIndicator;

import java.util.List;

public interface SecurityRule {
    String getRuleId();
    String getRuleName();
    List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads
    );
}
