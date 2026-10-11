package dev.guardianai.shield.url;

import dev.guardianai.util.Json;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Versioned registry of official domains for commonly impersonated organisations, loaded from the bundled resource
 * {@code dev/guardianai/safety/official_domains_v1.json}. Used to recognise exact official domains and to spot
 * impersonation. Being absent from the registry says nothing about a site.
 */
public final class OfficialDomainRegistry {

    public static final String RESOURCE = "/dev/guardianai/safety/official_domains_v1.json";

    public static final class Org {
        public final String id, name, category;
        public final List<String> keywords;
        public final Set<String> domains;

        Org(String id, String name, String category, List<String> keywords, Set<String> domains) {
            this.id = id;
            this.name = name;
            this.category = category;
            this.keywords = Collections.unmodifiableList(keywords);
            this.domains = Collections.unmodifiableSet(domains);
        }

        /** True if host is exactly an official domain or a subdomain of one (label boundary enforced). */
        public boolean owns(String asciiHost) {
            for (String d : domains) if (asciiHost.equals(d) || asciiHost.endsWith("." + d)) return true;
            return false;
        }
    }

    public final String version;
    public final List<Org> orgs;

    private OfficialDomainRegistry(String version, List<Org> orgs) {
        this.version = version;
        this.orgs = Collections.unmodifiableList(orgs);
    }

    private static volatile OfficialDomainRegistry bundled;

    /** The registry shipped with the app. Throws IllegalStateException if the bundled file is damaged. */
    public static OfficialDomainRegistry bundled() {
        if (bundled == null) {
            synchronized (OfficialDomainRegistry.class) {
                if (bundled == null) {
                    try (InputStream in = OfficialDomainRegistry.class.getResourceAsStream(RESOURCE)) {
                        if (in == null) throw new IllegalStateException("official domain registry missing");
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int r;
                        while ((r = in.read(buf)) != -1) out.write(buf, 0, r);
                        bundled = parse(new String(out.toByteArray(), StandardCharsets.UTF_8));
                    } catch (IllegalStateException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new IllegalStateException("official domain registry unreadable: " + e.getMessage());
                    }
                }
            }
        }
        return bundled;
    }

    public static OfficialDomainRegistry parse(String json) throws Json.ParseException {
        Map<String, Object> root = Json.parseObject(json);
        Long schema = Json.lng(root, "schemaVersion");
        if (schema == null || schema != 1) throw new Json.ParseException("unsupported registry schema");
        List<Object> arr = Json.arr(root, "organisations");
        if (arr == null) throw new Json.ParseException("no organisations");
        List<Org> orgs = new ArrayList<>();
        for (Object o : arr) {
            if (!(o instanceof Map)) throw new Json.ParseException("bad organisation entry");
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
            List<String> kw = Json.strList(m, "keywords");
            List<String> dom = Json.strList(m, "domains");
            String id = Json.str(m, "id"), name = Json.str(m, "name");
            if (id == null || name == null || kw == null || kw.isEmpty() || dom == null || dom.isEmpty()) {
                throw new Json.ParseException("incomplete organisation " + id);
            }
            for (String d : dom) if (!d.matches("^[a-z0-9.-]+$") || d.startsWith(".")) throw new Json.ParseException("bad domain " + d);
            orgs.add(new Org(id, name, Json.str(m, "category"), kw, new LinkedHashSet<>(dom)));
        }
        return new OfficialDomainRegistry(Json.str(root, "registryVersion"), orgs);
    }

    public Org ownerOf(String asciiHost) {
        for (Org o : orgs) if (o.owns(asciiHost)) return o;
        return null;
    }

    public Org byKeyword(String keyword) {
        for (Org o : orgs) if (o.keywords.contains(keyword)) return o;
        return null;
    }

    /** keyword -> official domains, for the lookalike heuristics. */
    public Map<String, Set<String>> keywordMap() {
        Map<String, Set<String>> m = new LinkedHashMap<>();
        for (Org o : orgs) for (String k : o.keywords) m.put(k, o.domains);
        return m;
    }
}
