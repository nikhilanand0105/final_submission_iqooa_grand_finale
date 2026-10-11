package dev.guardianai.rules;

import dev.guardianai.model.CertificateMetadata;
import dev.guardianai.model.DexInspectionResult;
import dev.guardianai.model.ManifestMetadata;
import dev.guardianai.model.ThreatIndicator;

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
