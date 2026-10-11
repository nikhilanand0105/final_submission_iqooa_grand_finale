package dev.saathi.ai.explain;

/** One analyzer finding the explanation may refer to. The id is the only handle the model may cite. */
public final class Finding {

    public final String id;
    public final String title;
    public final String description;
    public final String evidence;
    public final String severity;

    public Finding(String id, String title, String description, String evidence, String severity) {
        this.id = id;
        this.title = title == null ? "" : title;
        this.description = description == null ? "" : description;
        this.evidence = evidence == null ? "" : evidence;
        this.severity = severity == null ? "" : severity;
    }
}
