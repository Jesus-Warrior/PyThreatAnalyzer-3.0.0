
import json
import html as html_module
from datetime import datetime
import os
import re
import tempfile

from threat_intel import classify_malware_type, describe_script_findings, describe_document_findings
from risk_scoring import calculate_risk_score, calculate_layered_risk
from pythreat_version import __version__

REPORT_SCHEMA_VERSION = 1


class ReportWriteError(OSError):
    """Error legible al usuario al guardar un reporte."""


class ReportGenerator:
    def __init__(self):
        # Conservado por compatibilidad; se actualiza por cada reporte.
        self.timestamp = None

    def generate_report(self, file_path, virus_results, script_results, ai_results):
        """Build schema-v1 JSON data, with its schema marker as the first key."""
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        score, risk_level, indicators = calculate_risk_score(virus_results, script_results, ai_results)

        _, _, _, layers = calculate_layered_risk(virus_results or {}, script_results, ai_results)
        layer_scores = {
            name: {'score': l.score, 'confidence': l.confidence, 'findings': l.findings}
            for name, l in layers.items()
        }

        explanation = (virus_results or {}).get('explanation') or {}

        report = {
            'report_schema_version': REPORT_SCHEMA_VERSION,
            'metadata': {
                'file': file_path,
                'timestamp': self.timestamp,
                'tool': f'PyThreatAnalyzer v{__version__} (100% local)',
            },
            'virus_analysis': virus_results,
            'script_analysis': script_results,
            'ai_detection': ai_results,
            'summary': {
                'risk_score': score,
                'risk_level': risk_level,
                'indicators': indicators,
                'layer_scores': layer_scores,
                'analysis_status': (virus_results or {}).get('analysis_status', 'UNKNOWN'),
                'analysis_warnings': (virus_results or {}).get('analysis_warnings', []),
            },
        }
        if explanation:
            report['explanation'] = explanation
        return report

    def risk_level_for_virus(self, virus_results, script_results=None, ai_results=None):
        _score, level, _indicators = calculate_risk_score(virus_results, script_results, ai_results)
        return level

    @staticmethod
    def _report_timestamp(report, fallback=None):
        metadata = (report or {}).get('metadata', {}) or {}
        candidate = metadata.get('timestamp') or fallback or datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        candidate = os.path.basename(str(candidate))
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', candidate):
            candidate = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return candidate

    @staticmethod
    def _atomic_write(filename, content):
        directory = os.path.dirname(os.path.abspath(filename))
        temp_path = None
        try:
            os.makedirs(directory, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(prefix='.report-', suffix='.tmp', dir=directory)
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, filename)
            temp_path = None
        except OSError as e:
            raise ReportWriteError(f"No se pudo guardar '{filename}': {e}") from e
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def save_json(self, report, output_dir='reports'):
        timestamp = self._report_timestamp(report, self.timestamp)
        filename = os.path.join(output_dir, f"report_{timestamp}.json")
        content = json.dumps(report, indent=2, default=str)
        self._atomic_write(filename, content)
        return filename

    def save_html(self, report, output_dir='reports'):
        """FIX BUG #4: TODOS los valores procedentes del archivo analizado
        (ruta, hallazgos, indicadores, explicaciones) se escapan con
        html.escape antes de interpolarse: un nombre como
        '<script>alert(1)</script>.exe' ya no inyecta JS en el reporte."""
        timestamp = self._report_timestamp(report, self.timestamp)
        filename = os.path.join(output_dir, f"report_{timestamp}.html")

        summary = report.get('summary', {})
        layer_scores = summary.get('layer_scores', {})
        explanation = report.get('explanation', {})

        e = html_module.escape  # atajo

        layer_rows = ""
        for name, data in layer_scores.items():
            if data['score'] > 0:
                findings_str = '; '.join(data['findings'][:3]) if data['findings'] else '—'
                layer_rows += f"""
                <tr>
                    <td>{e(str(name))}</td>
                    <td>{data['score']}</td>
                    <td>{data['confidence']:.2f}</td>
                    <td>{e(findings_str)}</td>
                </tr>
                """

        mitre_items = ''.join(f'<li>{e(str(tech))}</li>' for tech in explanation.get('mitre_techniques', []))
        mitre_section = f'<ul>{mitre_items}</ul>' if mitre_items else '<p>Sin técnicas MITRE mapeadas.</p>'

        detail_rows = ""
        for det in explanation.get('detailed_explanations', []):
            detail_rows += f"""
                <tr>
                    <td>{e(str(det.get('indicator', '')))}</td>
                    <td>{e(str(det.get('description', '')))}</td>
                    <td>{e(str(det.get('location', '')))}</td>
                    <td>{e(str(det.get('severity', '')))}</td>
                    <td>{e(str(det.get('mitre') or '—'))}</td>
                </tr>
                """

        indicators_html = ''.join(f'<li>{e(str(ind))}</li>' for ind in summary.get('indicators', []))
        virus_data = report.get('virus_analysis') or {}
        yara_matches = ((virus_data.get('yara') or {}).get('matches') or [])
        yara_rows = ''.join(
            '<tr><td>' + e(str(match.get('rule', '?'))) + '</td><td>' +
            e(str((match.get('meta') or {}).get('severity', 'unknown'))) + '</td><td>' +
            e(str((match.get('meta') or {}).get('description', ''))) + '</td></tr>'
            for match in yara_matches
        )
        coverage_html = ''
        if summary.get('analysis_status') == 'INCOMPLETE':
            warning_items = ''.join(
                f'<li>{e(str(warning))}</li>'
                for warning in summary.get('analysis_warnings', [])
            )
            coverage_html = (
                '<p class="risk-high"><strong>Cobertura:</strong> ANÁLISIS INCOMPLETO; '
                'este resultado no confirma ausencia de amenazas.</p>'
                f'<ul>{warning_items}</ul>'
            )

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyThreatAnalyzer Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        h3 {{ color: #666; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .risk-critical {{ color: #d32f2f; font-weight: bold; }}
        .risk-high {{ color: #f57c00; font-weight: bold; }}
        .risk-medium {{ color: #fbc02d; }}
        .risk-low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <h1>🔍 PyThreatAnalyzer Report</h1>
    <p><strong>Archivo:</strong> {e(str(report['metadata']['file']))}</p>
    <p><strong>Fecha:</strong> {e(str(report['metadata']['timestamp']))}</p>

    <h2>📊 Resumen de Riesgo</h2>
    <p><strong>Nivel:</strong>
        <span class="risk-{e(str(summary.get('risk_level', 'UNKNOWN').lower()))}">
            {e(str(summary.get('risk_level', 'UNKNOWN')))}
        </span></p>
    <p><strong>Score:</strong> {summary.get('risk_score', 0)}/100</p>
    {coverage_html}

    <h3>🔬 Score por Capa</h3>
    <table>
        <tr><th>Capa</th><th>Score</th><th>Confianza</th><th>Hallazgos</th></tr>
        {layer_rows if layer_rows else '<tr><td colspan="4">Sin hallazgos significativos</td></tr>'}
    </table>

    <h3>⚠️ Indicadores</h3>
    <ul>
        {indicators_html}
    </ul>
    <h3>Coincidencias YARA</h3>
    <table><tr><th>Regla</th><th>Severidad</th><th>Descripción</th></tr>
        {yara_rows if yara_rows else '<tr><td colspan="3">Sin coincidencias YARA</td></tr>'}
    </table>

    <h2>🧠 Explicabilidad (Explainable AI)</h2>
    <p><strong>Resumen:</strong> {e(str(explanation.get('summary', 'No disponible')))}</p>
    <h3>🎯 Técnicas MITRE ATT&amp;CK</h3>
    {mitre_section}
    <h3>📍 Detalle de detecciones (qué y dónde)</h3>
    <table>
        <tr><th>Indicador</th><th>Descripción</th><th>Ubicación</th><th>Severidad</th><th>MITRE</th></tr>
        {detail_rows if detail_rows else '<tr><td colspan="5">Sin explicaciones detalladas</td></tr>'}
    </table>

    <h2>📋 Detalles Técnicos</h2>
    <pre>{e(json.dumps(report, indent=2, default=str))}</pre>
</body>
</html>"""

        self._atomic_write(filename, html_content)
        return filename
