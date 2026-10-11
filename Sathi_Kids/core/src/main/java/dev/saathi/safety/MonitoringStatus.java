package dev.saathi.safety;

import dev.saathi.ai.explain.ModelState;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Truthful background-protection status, derived only from real inputs (Android permission/service state, model
 * state, storage health, queue). Nothing here is assumed "on".
 */
public final class MonitoringStatus {

    public enum Overall { ACTIVE, PARTIALLY_ACTIVE, PERMISSION_REQUIRED, MONITORING_INTERRUPTED, PROTECTION_UNAVAILABLE }

    public enum Capability { NOTIFICATION_MONITORING, ALERT_DELIVERY, GEMMA_MODEL, SAFE_BROWSER, NETWORK_PROTECTION, LOCAL_STORAGE }

    public enum CapState {
        ACTIVE, PERMISSION_REQUIRED, SERVICE_DISCONNECTED, MODEL_READY, MODEL_LOADING, MODEL_NOT_INSTALLED, FALLBACK_ACTIVE,
        AVAILABLE, NOT_IMPLEMENTED, ERROR, ANALYSIS_PENDING
    }

    /** Real-world inputs collected by the app. */
    public static final class Inputs {
        public boolean notificationAccessGranted;
        public boolean listenerConnected;
        public long listenerLastConnectedAt;
        public boolean postNotificationsAllowed;
        public ModelState modelState = ModelState.UNAVAILABLE;
        public boolean storageHealthy = true;
        public int pendingAnalyses;
        public long lastProcessedAt;
        public int contentUnavailableCount;
        public int droppedForBackpressure;
    }

    public static final class Item {
        public final Capability capability;
        public final CapState state;
        public final String detail;
        public final String fix; // what the user can do, or "" if nothing needed

        Item(Capability c, CapState s, String d, String f) {
            capability = c;
            state = s;
            detail = d;
            fix = f;
        }
    }

    public final Overall overall;
    public final List<Item> items;

    private MonitoringStatus(Overall o, List<Item> items) {
        this.overall = o;
        this.items = Collections.unmodifiableList(items);
    }

    public static MonitoringStatus compute(Inputs in) {
        List<Item> items = new ArrayList<>();
        Item notif;
        if (!in.notificationAccessGranted) {
            notif = new Item(Capability.NOTIFICATION_MONITORING, CapState.PERMISSION_REQUIRED,
                    "Notification access is off, so incoming messages are not checked.", "Turn on notification access for Saathi Kids");
        } else if (!in.listenerConnected) {
            notif = new Item(Capability.NOTIFICATION_MONITORING, CapState.SERVICE_DISCONNECTED,
                    "Access is on, but Android hasn't connected Saathi's listener right now.", "Open Saathi once, or turn notification access off and on again");
        } else if (in.pendingAnalyses > 0) {
            notif = new Item(Capability.NOTIFICATION_MONITORING, CapState.ANALYSIS_PENDING,
                    in.pendingAnalyses + " message(s) waiting to be checked.", "");
        } else {
            notif = new Item(Capability.NOTIFICATION_MONITORING, CapState.ACTIVE,
                    "Checking message text that Android shows in notifications.", "");
        }
        items.add(notif);

        items.add(in.postNotificationsAllowed
                ? new Item(Capability.ALERT_DELIVERY, CapState.ACTIVE, "Saathi can show safety alerts.", "")
                : new Item(Capability.ALERT_DELIVERY, CapState.PERMISSION_REQUIRED, "Saathi isn't allowed to show notifications, so alerts can't appear.",
                "Allow notifications for Saathi Kids"));

        switch (in.modelState) {
            case READY:
            case GENERATING:
                items.add(new Item(Capability.GEMMA_MODEL, CapState.MODEL_READY, "On-device Gemma model is loaded and used first.", ""));
                break;
            case INITIALIZING:
                items.add(new Item(Capability.GEMMA_MODEL, CapState.MODEL_LOADING, "Loading the model; rules are used meanwhile.", ""));
                break;
            case UNAVAILABLE:
                items.add(new Item(Capability.GEMMA_MODEL, CapState.MODEL_NOT_INSTALLED, "No model installed; Saathi's safety rules are used.",
                        "An adult can install a Gemma .litertlm model (see setup guide)"));
                break;
            default:
                items.add(new Item(Capability.GEMMA_MODEL, CapState.FALLBACK_ACTIVE, in.modelState.getDescription() + "; Saathi's safety rules are used.",
                        in.modelState == ModelState.CLOSED ? "Load the model in Settings" : ""));
                break;
        }
        items.add(new Item(Capability.SAFE_BROWSER, CapState.AVAILABLE, "Websites opened in Saathi Safe Browser are checked before they load.", ""));
        items.add(new Item(Capability.NETWORK_PROTECTION, CapState.NOT_IMPLEMENTED,
                "Other browsers (like Chrome) are not checked by Saathi.", ""));
        items.add(in.storageHealthy
                ? new Item(Capability.LOCAL_STORAGE, CapState.ACTIVE, "Results are saved on this phone.", "")
                : new Item(Capability.LOCAL_STORAGE, CapState.ERROR, "Saathi couldn't save results; alerts may not be kept.", "Free up storage or reinstall"));

        Overall o;
        if (!in.storageHealthy) o = Overall.PROTECTION_UNAVAILABLE;
        else if (!in.notificationAccessGranted) o = Overall.PERMISSION_REQUIRED;
        else if (!in.listenerConnected) o = Overall.MONITORING_INTERRUPTED;
        else if (!in.postNotificationsAllowed) o = Overall.PARTIALLY_ACTIVE;
        else o = Overall.ACTIVE;
        return new MonitoringStatus(o, items);
    }

    public Item item(Capability c) {
        for (Item i : items) if (i.capability == c) return i;
        return null;
    }
}
