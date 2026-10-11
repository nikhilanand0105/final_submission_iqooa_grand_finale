package dev.guardianai.family;

/** Validation for locally saved trusted-adult contacts. Returns a child-friendly error, or null if valid. */
public final class TrustedAdultValidator {

    private TrustedAdultValidator() {}

    public static String validate(String name, String relationship, String phone) {
        String n = name == null ? "" : name.trim();
        if (n.isEmpty()) return "Please type their name";
        if (n.length() > 40) return "Name is too long (40 characters max)";
        if (!n.matches("^[\\p{L}\\p{M}\\p{N} .'-]+$")) return "Name can only have letters, numbers and spaces";
        String r = relationship == null ? "" : relationship.trim();
        if (r.length() > 30) return "Relationship is too long (30 characters max)";
        if (!r.isEmpty() && !r.matches("^[\\p{L}\\p{M} .'/-]+$")) return "Relationship can only have letters";
        String p = phone == null ? "" : phone.trim();
        if (!p.isEmpty()) {
            if (!p.matches("^\\+?[0-9 ()-]{7,20}$")) return "Phone number can only have digits, spaces, + and -";
            int digits = p.replaceAll("[^0-9]", "").length();
            if (digits < 7 || digits > 15) return "Phone number should have 7 to 15 digits";
        }
        return null;
    }

    /** Digits and a leading '+' only, for use in a dial intent. */
    public static String dialable(String phone) {
        if (phone == null) return "";
        String t = phone.trim();
        String d = t.replaceAll("[^0-9]", "");
        return t.startsWith("+") ? "+" + d : d;
    }
}
