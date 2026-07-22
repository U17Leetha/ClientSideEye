package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.Finding.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class FindingsTableModelTest {

    private static Finding finding(String type, Severity severity, int confidence, String title) {
        return new Finding(
                type, severity, confidence,
                "https://example.test/app", "example.test",
                title, "summary", "evidence", "recommendation"
        );
    }

    @Test
    void reportsRowAndColumnCounts() {
        FindingsTableModel model = new FindingsTableModel(f -> false);
        model.setRows(List.of(
                finding("TYPE_A", Severity.HIGH, 90, "Finding A"),
                finding("TYPE_B", Severity.LOW, 30, "Finding B")
        ));

        assertEquals(2, model.getRowCount());
        assertEquals(7, model.getColumnCount());
        assertEquals("Severity", model.getColumnName(0));
        assertEquals("URL", model.getColumnName(6));
    }

    @Test
    void exposesExpectedColumnValues() {
        FindingsTableModel model = new FindingsTableModel(f -> false);
        Finding f = finding("TYPE_A", Severity.HIGH, 90, "Finding A");
        model.setRows(List.of(f));

        assertEquals("HIGH", model.getValueAt(0, 0));
        assertEquals("90", model.getValueAt(0, 1));
        assertEquals("", model.getValueAt(0, 2));
        assertEquals("TYPE_A", model.getValueAt(0, 3));
        assertEquals("example.test", model.getValueAt(0, 4));
        assertEquals("Finding A", model.getValueAt(0, 5));
        assertEquals("https://example.test/app", model.getValueAt(0, 6));
    }

    @Test
    void falsePositiveColumnReflectsSuppliedPredicate() {
        Finding flagged = finding("TYPE_A", Severity.HIGH, 90, "Flagged");
        Finding notFlagged = finding("TYPE_B", Severity.LOW, 30, "Not flagged");
        Set<String> falsePositiveKeys = Set.of(flagged.stableKey());

        FindingsTableModel model = new FindingsTableModel(f -> falsePositiveKeys.contains(f.stableKey()));
        model.setRows(List.of(flagged, notFlagged));

        assertEquals("yes", model.getValueAt(0, 2));
        assertEquals("", model.getValueAt(1, 2));
    }

    @Test
    void getAtReturnsNullForOutOfRangeIndices() {
        FindingsTableModel model = new FindingsTableModel(f -> false);
        model.setRows(List.of(finding("TYPE_A", Severity.HIGH, 90, "Finding A")));

        assertNull(model.getAt(-1));
        assertNull(model.getAt(5));
    }

    @Test
    void rowsSnapshotIsIndependentOfSubsequentSetRowsCalls() {
        FindingsTableModel model = new FindingsTableModel(f -> false);
        Finding first = finding("TYPE_A", Severity.HIGH, 90, "First");
        model.setRows(List.of(first));

        List<Finding> snapshot = model.rowsSnapshot();
        model.setRows(List.of(finding("TYPE_B", Severity.LOW, 30, "Second")));

        assertEquals(1, snapshot.size());
        assertEquals("First", snapshot.get(0).title());
    }

    @Test
    void setRowsWithNullClearsTable() {
        FindingsTableModel model = new FindingsTableModel(f -> false);
        model.setRows(List.of(finding("TYPE_A", Severity.HIGH, 90, "Finding A")));
        model.setRows(null);

        assertEquals(0, model.getRowCount());
    }

    @Test
    void nullFalsePositivePredicateDefaultsToFalse() {
        FindingsTableModel model = new FindingsTableModel(null);
        model.setRows(List.of(finding("TYPE_A", Severity.HIGH, 90, "Finding A")));

        assertEquals("", model.getValueAt(0, 2));
    }
}
