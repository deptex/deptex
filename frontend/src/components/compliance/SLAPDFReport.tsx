import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
} from '@react-pdf/renderer';
import type { SlaComplianceResponse, SlaExportSummary } from '../../lib/api';

const styles = StyleSheet.create({
  page: { padding: 40, fontSize: 10, fontFamily: 'Helvetica' },
  title: { fontSize: 18, marginBottom: 8 },
  subtitle: { fontSize: 11, marginBottom: 20, color: '#64748b' },
  section: { marginBottom: 16 },
  sectionTitle: { fontSize: 12, marginBottom: 8, fontWeight: 'bold' },
  row: { flexDirection: 'row', marginBottom: 4 },
  label: { width: 140 },
  value: { flex: 1 },
  table: { marginTop: 8 },
  tableRow: { flexDirection: 'row', borderBottomWidth: 1, borderBottomColor: '#e2e8f0', paddingVertical: 6 },
  tableHeader: { flexDirection: 'row', borderBottomWidth: 2, borderBottomColor: '#94a3b8', paddingVertical: 6, fontWeight: 'bold' },
  col1: { width: '24%' },
  col2: { width: '18%' },
  col3: { width: '12%' },
  col4: { width: '18%' },
  col5: { width: '14%' },
  col6: { width: '14%' },
});

interface SLAPDFReportProps {
  orgName: string;
  compliance: SlaComplianceResponse;
  exportSummary: SlaExportSummary;
  exportRows: Array<{ project_name: string; osv_id: string; severity: string; sla_status: string; detected_at: string; deadline: string | null }>;
}

export default function SLAPDFReport({ orgName, compliance, exportSummary, exportRows }: SLAPDFReportProps) {
  const dateRange = `${exportSummary.time_range} ending ${new Date().toLocaleDateString()}`;
  return (
    <Document>
      <Page size="A4" style={styles.page}>
        <Text style={styles.title}>SLA Compliance Report — {orgName}</Text>
        <Text style={styles.subtitle}>{dateRange}</Text>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Summary</Text>
          <View style={styles.row}>
            <Text style={styles.label}>Overall compliance:</Text>
            <Text style={styles.value}>{compliance.overall_compliance_percent}%</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Current breaches:</Text>
            <Text style={styles.value}>{compliance.current_breaches}</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Met within SLA:</Text>
            <Text style={styles.value}>{exportSummary.met_within_sla}</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Resolved late:</Text>
            <Text style={styles.value}>{exportSummary.resolved_late}</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Total vulnerabilities:</Text>
            <Text style={styles.value}>{exportSummary.total_vulnerabilities}</Text>
          </View>
        </View>

        {Object.keys(compliance.average_mttr_by_severity).length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Average MTTR by severity (hours)</Text>
            {Object.entries(compliance.average_mttr_by_severity).map(([sev, hours]) => (
              <View key={sev} style={styles.row}>
                <Text style={styles.label}>{sev}:</Text>
                <Text style={styles.value}>{hours.toFixed(1)}</Text>
              </View>
            ))}
          </View>
        )}

        {exportRows.length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Violations / status detail</Text>
            <View style={styles.table}>
              <View style={styles.tableHeader}>
                <Text style={styles.col1}>Project</Text>
                <Text style={styles.col2}>OSV ID</Text>
                <Text style={styles.col3}>Severity</Text>
                <Text style={styles.col4}>SLA status</Text>
                <Text style={styles.col5}>Detected</Text>
                <Text style={styles.col6}>Deadline</Text>
              </View>
              {exportRows.slice(0, 50).map((row, i) => (
                <View key={i} style={styles.tableRow}>
                  <Text style={styles.col1}>{row.project_name}</Text>
                  <Text style={styles.col2}>{row.osv_id}</Text>
                  <Text style={styles.col3}>{row.severity}</Text>
                  <Text style={styles.col4}>{row.sla_status}</Text>
                  <Text style={styles.col5}>{row.detected_at ? new Date(row.detected_at).toLocaleDateString() : '—'}</Text>
                  <Text style={styles.col6}>{row.deadline ? new Date(row.deadline).toLocaleDateString() : '—'}</Text>
                </View>
              ))}
              {exportRows.length > 50 && (
                <Text style={{ marginTop: 8 }}>… and {exportRows.length - 50} more (see CSV export).</Text>
              )}
            </View>
          </View>
        )}
      </Page>
    </Document>
  );
}
