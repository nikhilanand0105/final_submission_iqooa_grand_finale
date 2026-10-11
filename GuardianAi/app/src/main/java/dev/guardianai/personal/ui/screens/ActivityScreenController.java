package dev.guardianai.personal.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.personal.R;
import dev.guardianai.personal.data.db.ScanRecord;
import dev.guardianai.personal.data.db.SecurityAuditRepository;
import dev.guardianai.personal.ui.components.DetailSheetDialog;
import dev.guardianai.personal.ui.model.ActivityEvent;
import dev.guardianai.personal.ui.state.AppState;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ActivityScreenController {

    private final Activity activity;
    private final float density;
    private ScrollView rootView;

    private EditText etSearch;
    private LinearLayout containerChips;
    private LinearLayout containerEventsList;
    private LinearLayout emptyStateContainer;
    private TextView tvEmptyTitle;
    private TextView tvEmptySubtitle;

    private String currentSearchQuery = "";
    private String selectedOperationType = null; // null = ALL, "MESSAGE", "LINK", "APK", "PERMISSION_AUDIT"
    private List<ScanRecord> cachedScans = new ArrayList<>();

    public ActivityScreenController(Activity activity) {
        this.activity = activity;
        this.density = activity.getResources().getDisplayMetrics().density;
        createView();
    }

    public View getView() {
        return rootView;
    }

    private void createView() {
        rootView = new ScrollView(activity);
        rootView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        rootView.setFillViewport(true);
        rootView.setBackgroundColor(0xFFF7F7F5);

        LinearLayout layout = new LinearLayout(activity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding((int) (20 * density), (int) (16 * density), (int) (20 * density), (int) (100 * density));

        // 1. Header with Clear History button
        LinearLayout headerRow = new LinearLayout(activity);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        headerRow.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout titleCol = new LinearLayout(activity);
        titleCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tcp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        titleCol.setLayoutParams(tcp);

        TextView title = new TextView(activity);
        title.setText("SECURITY AUDIT & ACTIVITY");
        title.setTextSize(22);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        titleCol.addView(title);

        TextView sub = new TextView(activity);
        sub.setText("Chronological forensic telemetry and threat interceptions stored locally on-device");
        sub.setTextSize(13);
        sub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        sp.topMargin = (int) (4 * density);
        sub.setLayoutParams(sp);
        titleCol.addView(sub);

        headerRow.addView(titleCol);

        // Clear History button
        Button btnClear = new Button(activity);
        btnClear.setText("Clear");
        btnClear.setTextSize(12);
        btnClear.setTextColor(0xFF888888);
        btnClear.setBackgroundResource(R.drawable.bg_pill_dark);
        btnClear.setPadding((int) (12 * density), 0, (int) (12 * density), 0);
        LinearLayout.LayoutParams cbParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                (int) (36 * density)
        );
        btnClear.setLayoutParams(cbParams);
        btnClear.setOnClickListener(v -> confirmClearHistory());
        headerRow.addView(btnClear);

        layout.addView(headerRow);

        // 2. Search Bar
        etSearch = new EditText(activity);
        etSearch.setHint("🔍 Search alerts, DEX hooks, domains...");
        etSearch.setHintTextColor(0xFF888888);
        etSearch.setTextColor(0xFF141414);
        etSearch.setTextSize(13);
        etSearch.setBackgroundResource(R.drawable.bg_input_field);
        etSearch.setPadding((int) (16 * density), (int) (12 * density), (int) (16 * density), (int) (12 * density));
        LinearLayout.LayoutParams searchParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        searchParams.topMargin = (int) (14 * density);
        etSearch.setLayoutParams(searchParams);
        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                currentSearchQuery = s.toString().trim().toLowerCase(Locale.ROOT);
                applyFilterAndRender();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });
        layout.addView(etSearch);

        // 3. Category Filter Chips (Horizontal Scroll)
        HorizontalScrollView hsv = new HorizontalScrollView(activity);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hp.topMargin = (int) (12 * density);
        hp.bottomMargin = (int) (16 * density);
        hsv.setLayoutParams(hp);

        containerChips = new LinearLayout(activity);
        containerChips.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(containerChips);
        layout.addView(hsv);

        buildChips();

        // 4. Events Container
        containerEventsList = new LinearLayout(activity);
        containerEventsList.setOrientation(LinearLayout.VERTICAL);
        layout.addView(containerEventsList);

        // 5. Honest Empty State Container
        emptyStateContainer = new LinearLayout(activity);
        emptyStateContainer.setOrientation(LinearLayout.VERTICAL);
        emptyStateContainer.setGravity(Gravity.CENTER);
        emptyStateContainer.setPadding(0, (int) (48 * density), 0, (int) (48 * density));
        emptyStateContainer.setVisibility(View.GONE);

        TextView emptyIcon = new TextView(activity);
        emptyIcon.setText("🛡️");
        emptyIcon.setTextSize(36);
        emptyIcon.setGravity(Gravity.CENTER);
        emptyStateContainer.addView(emptyIcon);

        tvEmptyTitle = new TextView(activity);
        tvEmptyTitle.setText("No activity recorded yet.");
        tvEmptyTitle.setTextSize(16);
        tvEmptyTitle.setTextColor(0xFF141414);
        tvEmptyTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        tvEmptyTitle.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams etp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        etp.topMargin = (int) (8 * density);
        tvEmptyTitle.setLayoutParams(etp);
        emptyStateContainer.addView(tvEmptyTitle);

        tvEmptySubtitle = new TextView(activity);
        tvEmptySubtitle.setText("Run security scans from the Scan tab to populate your persistent local audit ledger.");
        tvEmptySubtitle.setTextSize(13);
        tvEmptySubtitle.setTextColor(0xFF888888);
        tvEmptySubtitle.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams esp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        esp.topMargin = (int) (4 * density);
        tvEmptySubtitle.setLayoutParams(esp);
        emptyStateContainer.addView(tvEmptySubtitle);

        layout.addView(emptyStateContainer);

        rootView.addView(layout);
        render();
    }

    private void buildChips() {
        containerChips.removeAllViews();

        containerChips.addView(createFilterChip("ALL", null));
        containerChips.addView(createFilterChip("MESSAGES", "MESSAGE"));
        containerChips.addView(createFilterChip("LINKS", "LINK"));
        containerChips.addView(createFilterChip("FILES / APKS", "APK"));
        containerChips.addView(createFilterChip("DEVICE", "PERMISSION_AUDIT"));
    }

    private Button createFilterChip(String label, String opType) {
        Button chip = new Button(activity);
        chip.setText(label);
        chip.setTextSize(11);
        boolean isSelected = (selectedOperationType == null && opType == null) ||
                (selectedOperationType != null && selectedOperationType.equals(opType));

        if (isSelected) {
            chip.setTextColor(0xFFFFFFFF);
            chip.setBackgroundResource(R.drawable.bg_pill_black);
            chip.setTypeface(null, android.graphics.Typeface.BOLD);
        } else {
            chip.setTextColor(0xFF666666);
            chip.setBackgroundResource(R.drawable.bg_pill_dark);
        }

        chip.setOnClickListener(v -> {
            selectedOperationType = opType;
            buildChips();
            loadRecordsFromRepository();
        });

        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                (int) (36 * density)
        );
        cp.rightMargin = (int) (8 * density);
        chip.setLayoutParams(cp);
        return chip;
    }

    public void render() {
        loadRecordsFromRepository();
    }

    private void loadRecordsFromRepository() {
        SecurityAuditRepository repo = AppState.get().getAuditRepository();
        if (repo != null) {
            if (selectedOperationType == null) {
                repo.getAllScans(records -> {
                    this.cachedScans = records != null ? records : new ArrayList<>();
                    applyFilterAndRender();
                });
            } else {
                repo.getScansByType(selectedOperationType, records -> {
                    this.cachedScans = records != null ? records : new ArrayList<>();
                    applyFilterAndRender();
                });
            }
        } else {
            applyFilterAndRender();
        }
    }

    private void applyFilterAndRender() {
        containerEventsList.removeAllViews();
        boolean senior = AppState.get().isSeniorMode();
        List<ScanRecord> filtered = new ArrayList<>();

        for (ScanRecord scan : cachedScans) {
            // Text search query filter
            if (!currentSearchQuery.isEmpty()) {
                String source = scan.getSource().toLowerCase(Locale.ROOT);
                String summary = scan.getSummary().toLowerCase(Locale.ROOT);
                String verdict = scan.getVerdict().toLowerCase(Locale.ROOT);
                if (!source.contains(currentSearchQuery) && !summary.contains(currentSearchQuery) && !verdict.contains(currentSearchQuery)) {
                    continue;
                }
            }
            filtered.add(scan);
        }

        if (filtered.isEmpty()) {
            emptyStateContainer.setVisibility(View.VISIBLE);
            if (!currentSearchQuery.isEmpty() || selectedOperationType != null) {
                tvEmptyTitle.setText("No matching security events");
                tvEmptySubtitle.setText("Try adjusting your search query or category filter.");
            } else {
                tvEmptyTitle.setText("No activity recorded yet.");
                tvEmptySubtitle.setText("Run security scans from the Scan tab to populate your persistent local audit ledger.");
            }
        } else {
            emptyStateContainer.setVisibility(View.GONE);
            for (ScanRecord scan : filtered) {
                ActivityEvent event = AppState.mapScanRecordToActivityEvent(scan, null);
                containerEventsList.addView(createEventCard(event, senior));
            }
        }
    }

    private View createEventCard(ActivityEvent ev, boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (12 * density);
        card.setLayoutParams(params);
        card.setOnClickListener(v -> DetailSheetDialog.showEventDetails(activity, ev));

        // Top row: Category, Severity, Timestamp
        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvCategory = new TextView(activity);
        tvCategory.setText(ev.getCategory().getDisplayName().toUpperCase());
        tvCategory.setTextSize(senior ? 12 : 10);
        tvCategory.setTextColor(0xFF141414);
        tvCategory.setBackgroundResource(R.drawable.bg_pill_dark);
        tvCategory.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));
        topRow.addView(tvCategory);

        TextView tvSeverity = new TextView(activity);
        LinearLayout.LayoutParams svp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        svp.leftMargin = (int) (6 * density);
        tvSeverity.setLayoutParams(svp);
        tvSeverity.setText(ev.getSeverity().name());
        tvSeverity.setTextSize(senior ? 12 : 10);
        tvSeverity.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));

        if (ev.getSeverity() == ThreatSeverity.CRITICAL) {
            tvSeverity.setTextColor(0xFFA63232);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_crimson);
        } else if (ev.getSeverity() == ThreatSeverity.HIGH) {
            tvSeverity.setTextColor(0xFF855A12);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_amber);
        } else {
            tvSeverity.setTextColor(0xFF386B57);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_emerald);
        }
        topRow.addView(tvSeverity);

        View space = new View(activity);
        topRow.addView(space, new LinearLayout.LayoutParams(0, 1, 1f));

        TextView tvTime = new TextView(activity);
        SimpleDateFormat sdf = new SimpleDateFormat("hh:mm a", Locale.getDefault());
        tvTime.setText(sdf.format(ev.getTimestamp()));
        tvTime.setTextSize(senior ? 12 : 11);
        tvTime.setTextColor(0xFF888888);
        topRow.addView(tvTime);

        card.addView(topRow);

        // Title
        TextView tvTitle = new TextView(activity);
        tvTitle.setText(ev.getTitle());
        tvTitle.setTextSize(senior ? 17 : 15);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tp.topMargin = (int) (8 * density);
        tvTitle.setLayoutParams(tp);
        card.addView(tvTitle);

        // Summary
        TextView tvSum = new TextView(activity);
        tvSum.setText(ev.getSummary());
        tvSum.setTextSize(senior ? 14 : 12);
        tvSum.setTextColor(0xFF666666);
        tvSum.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        sp.topMargin = (int) (4 * density);
        tvSum.setLayoutParams(sp);
        card.addView(tvSum);

        // Remediation Link
        TextView tvAction = new TextView(activity);
        tvAction.setText(ev.getActionLabel() + " →");
        tvAction.setTextSize(senior ? 14 : 12);
        tvAction.setTextColor(0xFF141414);
        tvAction.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ap.topMargin = (int) (10 * density);
        tvAction.setLayoutParams(ap);
        card.addView(tvAction);

        return card;
    }

    private void confirmClearHistory() {
        new AlertDialog.Builder(activity)
                .setTitle("Clear Audit History")
                .setMessage("Are you sure you want to prune and clear all security audit records from on-device local storage?")
                .setPositiveButton("Clear All", (dialog, which) -> {
                    AppState.get().clearLocalAuditCache(() -> {
                        Toast.makeText(activity, "Local security audit records cleared.", Toast.LENGTH_SHORT).show();
                        render();
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
