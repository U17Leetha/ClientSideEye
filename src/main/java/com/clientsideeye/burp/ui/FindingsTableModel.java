package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Table model backing the ClientSideEye findings table.
 *
 * <p>Deliberately a standalone, dependency-injected class (rather than a private inner class of
 * {@code ClientSideEyeTab}) so it can be unit-tested without constructing a {@code JPanel}/
 * {@code MontoyaApi}-backed UI. The false-positive check is supplied as a {@link Predicate}
 * instead of being read directly from the tab's mutable state, which is the only piece of
 * external state this model needs.
 */
final class FindingsTableModel extends AbstractTableModel {

    static final String[] COLUMNS = {"Severity", "Confidence", "FP", "Type", "Host", "Title", "URL"};

    private final Predicate<Finding> falsePositiveCheck;
    private List<Finding> rows = List.of();

    FindingsTableModel(Predicate<Finding> falsePositiveCheck) {
        this.falsePositiveCheck = falsePositiveCheck == null ? f -> false : falsePositiveCheck;
    }

    void setRows(List<Finding> rows) {
        this.rows = rows == null ? List.of() : rows;
        fireTableDataChanged();
    }

    List<Finding> rowsSnapshot() {
        return new ArrayList<>(rows);
    }

    Finding getAt(int row) {
        if (row < 0 || row >= rows.size()) return null;
        return rows.get(row);
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Finding f = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> f.severity().name();
            case 1 -> String.valueOf(f.confidence());
            case 2 -> falsePositiveCheck.test(f) ? "yes" : "";
            case 3 -> f.type();
            case 4 -> f.host();
            case 5 -> f.title();
            case 6 -> f.url();
            default -> "";
        };
    }
}
