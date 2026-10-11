package dev.saathi.kids.ui.model;

/**
 * A trusted adult saved on this phone by the child. Saving a contact does NOT notify or verify the person and
 * does not make them able to receive Saathi help requests; only adults paired through Saathi Personal can.
 */
public class TrustedAdult {
    private final String id;
    private final String name;
    private final String relation;
    private final String phone;
    private final int displayOrder;
    private final long createdTimestamp;
    private final long updatedTimestamp;

    public TrustedAdult(String id, String name, String relation, String phone, int displayOrder,
                        long createdTimestamp, long updatedTimestamp) {
        this.id = id;
        this.name = name == null ? "" : name.trim();
        this.relation = relation == null ? "" : relation.trim();
        this.phone = phone == null ? "" : phone.trim();
        this.displayOrder = displayOrder;
        this.createdTimestamp = createdTimestamp;
        this.updatedTimestamp = updatedTimestamp;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getRelation() { return relation; }
    public String getPhone() { return phone; }
    public int getDisplayOrder() { return displayOrder; }
    public long getCreatedTimestamp() { return createdTimestamp; }
    public long getUpdatedTimestamp() { return updatedTimestamp; }

    public String label() {
        return relation.isEmpty() ? name : name + " (" + relation + ")";
    }
}
