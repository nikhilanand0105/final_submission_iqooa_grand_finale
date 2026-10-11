package dev.saathi.shield.url;

import dev.saathi.util.Json;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Verified registry of legitimate Indian banking institutions and their official domains under the RBI .bank.in
 * namespace, along with officially linked legacy aliases and banking portals.
 *
 * Source: Reserve Bank of India circular RBI/2023-24/104 (Migration to .bank.in domain) and GoI Public/Private Sector
 * Bank Directories.
 */
public final class BankDomainRegistry {

    public static final String RESOURCE = "/dev/saathi/safety/bank_domains_v1.json";

    public static final class BankEntry {
        public final String bankId;
        public final String bankName;
        public final String category;
        public final String primaryDomain;
        public final String purpose;
        public final boolean subdomainsPermitted;
        public final String subdomainsRationale;
        public final Set<String> legacyAliases;
        public final String officialSourceUrl;
        public final String verificationDate;
        public final String status;
        public final String limitations;

        BankEntry(String bankId, String bankName, String category, String primaryDomain, String purpose,
                  boolean subdomainsPermitted, String subdomainsRationale, Set<String> legacyAliases,
                  String officialSourceUrl, String verificationDate, String status, String limitations) {
            this.bankId = bankId;
            this.bankName = bankName;
            this.category = category;
            this.primaryDomain = primaryDomain;
            this.purpose = purpose;
            this.subdomainsPermitted = subdomainsPermitted;
            this.subdomainsRationale = subdomainsRationale;
            this.legacyAliases = Collections.unmodifiableSet(legacyAliases);
            this.officialSourceUrl = officialSourceUrl;
            this.verificationDate = verificationDate;
            this.status = status;
            this.limitations = limitations;
        }

        /** Checks if host is exactly the primary official domain or a valid subdomain when permitted. */
        public boolean matchesPrimary(String host) {
            if (host == null || host.isEmpty()) return false;
            String h = host.toLowerCase(Locale.ROOT);
            if (h.equals(primaryDomain)) return true;
            if (subdomainsPermitted && h.endsWith("." + primaryDomain)) return true;
            return false;
        }

        /** Checks if host is an officially linked legacy domain or valid portal. */
        public boolean matchesLegacy(String host) {
            if (host == null || host.isEmpty()) return false;
            String h = host.toLowerCase(Locale.ROOT);
            for (String alias : legacyAliases) {
                if (h.equals(alias) || h.endsWith("." + alias)) return true;
            }
            return false;
        }
    }

    public final String version;
    public final String verificationDate;
    public final String authoritySource;
    public final List<BankEntry> banks;

    private BankDomainRegistry(String version, String verificationDate, String authoritySource, List<BankEntry> banks) {
        this.version = version;
        this.verificationDate = verificationDate;
        this.authoritySource = authoritySource;
        this.banks = Collections.unmodifiableList(banks);
    }

    private static volatile BankDomainRegistry bundled;

    /** Returns bundled bank registry. Safe to call repeatedly. */
    public static BankDomainRegistry bundled() {
        if (bundled == null) {
            synchronized (BankDomainRegistry.class) {
                if (bundled == null) {
                    try (InputStream in = BankDomainRegistry.class.getResourceAsStream(RESOURCE)) {
                        if (in == null) throw new IllegalStateException("bank domain registry resource missing");
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int r;
                        while ((r = in.read(buf)) != -1) out.write(buf, 0, r);
                        bundled = parse(new String(out.toByteArray(), StandardCharsets.UTF_8));
                    } catch (IllegalStateException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new IllegalStateException("bank domain registry unreadable: " + e.getMessage(), e);
                    }
                }
            }
        }
        return bundled;
    }

    public static BankDomainRegistry parse(String json) throws Json.ParseException {
        Map<String, Object> root = Json.parseObject(json);
        Long schema = Json.lng(root, "schemaVersion");
        if (schema == null || schema != 1) throw new Json.ParseException("unsupported bank registry schema");
        List<Object> arr = Json.arr(root, "banks");
        if (arr == null) throw new Json.ParseException("no bank entries");
        List<BankEntry> list = new ArrayList<>();
        for (Object o : arr) {
            if (!(o instanceof Map)) throw new Json.ParseException("bad bank entry");
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
            String id = Json.str(m, "bankId");
            String name = Json.str(m, "bankName");
            String primary = Json.str(m, "primaryDomain");
            if (id == null || name == null || primary == null) {
                throw new Json.ParseException("incomplete bank entry: " + id);
            }
            List<String> aliases = Json.strList(m, "legacyAliases");
            Set<String> aliasSet = new LinkedHashSet<>(aliases != null ? aliases : Collections.emptyList());
            Boolean subPermitted = Json.bool(m, "subdomainsPermitted");
            list.add(new BankEntry(
                    id,
                    name,
                    Json.str(m, "category"),
                    primary.toLowerCase(Locale.ROOT),
                    Json.str(m, "purpose"),
                    subPermitted != null && subPermitted,
                    Json.str(m, "subdomainsRationale"),
                    aliasSet,
                    Json.str(m, "officialSourceUrl"),
                    Json.str(m, "verificationDate"),
                    Json.str(m, "status"),
                    Json.str(m, "limitations")
            ));
        }
        return new BankDomainRegistry(
                Json.str(root, "registryVersion"),
                Json.str(root, "verificationDate"),
                Json.str(root, "authoritySource"),
                list
        );
    }

    /** Finds bank entry by exact hostname (primary or legacy). */
    public BankEntry findBank(String asciiHost) {
        if (asciiHost == null || asciiHost.isEmpty()) return null;
        String h = asciiHost.toLowerCase(Locale.ROOT);
        for (BankEntry b : banks) {
            if (b.matchesPrimary(h) || b.matchesLegacy(h)) return b;
        }
        return null;
    }

    /** True if host matches verified official primary domain of any bank in the registry. */
    public boolean isVerifiedOfficial(String asciiHost) {
        if (asciiHost == null || asciiHost.isEmpty()) return false;
        String h = asciiHost.toLowerCase(Locale.ROOT);
        for (BankEntry b : banks) {
            if (b.matchesPrimary(h)) return true;
        }
        return false;
    }

    /** True if host matches an officially linked legacy domain or verified portal of any bank in the registry. */
    public boolean isOfficiallyLinkedLegacy(String asciiHost) {
        if (asciiHost == null || asciiHost.isEmpty()) return false;
        String h = asciiHost.toLowerCase(Locale.ROOT);
        for (BankEntry b : banks) {
            if (b.matchesLegacy(h)) return true;
        }
        return false;
    }
}
