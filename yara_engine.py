"""
Motor YARA robusto: antes, si UN SOLO archivo .yara en el directorio tenía
un error (módulo no soportado, sintaxis rota, regla de otro usuario mal
copiada), `yara.compile(filepaths=...)` fallaba por completo y el escaneo
quedaba deshabilitado. Ahora:
  1. Intenta compilar todo junto (rápido, camino feliz).
  2. Si falla, compila archivo por archivo, descarta los rotos y compila
     solo con los válidos, reportando cuáles se excluyeron.
"""

import os
import logging
import hashlib

try:
    import yara
except ImportError:
    yara = None


logger = logging.getLogger('PyThreatAnalyzer')


class YARAEngine:
    def __init__(self, rules_path='yara_rules/', timeout_seconds=10):
        self.rules_path = rules_path
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.skipped_rules = []
        self.loaded_rule_count = 0
        self.rules = self._compile_rules(rules_path) if yara else None

    def _find_rule_files(self, path):
        rule_files = {}
        if not os.path.isdir(path):
            return rule_files
        for root, _dirs, files in os.walk(path):
            for file in files:
                if not file.endswith(('.yara', '.yar')):
                    continue
                full_path = os.path.join(root, file)
                # Namespace único: nombre de archivo + hash corto de la ruta,
                # para evitar colisiones cuando hay subcarpetas con archivos
                # del mismo nombre (ej. varias reglas "generic.yar").
                path_digest = hashlib.sha256(os.path.abspath(full_path).encode('utf-8')).hexdigest()[:16]
                namespace = f"rule_{path_digest}"
                rule_files[namespace] = full_path
        return rule_files

    def _compile_rules(self, path):
        rule_files = self._find_rule_files(path)
        if not rule_files:
            return None

        # Camino feliz: compilar todo junto
        try:
            compiled = yara.compile(filepaths=rule_files)
            self.loaded_rule_count = len(rule_files)
            return compiled
        except yara.Error:
            pass  # cae al modo robusto abajo

        # Modo robusto: probar cada archivo individualmente y quedarnos
        # solo con los que compilan, en vez de perder TODAS las reglas
        # por un solo archivo roto.
        valid_files = {}
        for namespace, full_path in rule_files.items():
            try:
                yara.compile(filepath=full_path)
                valid_files[namespace] = full_path
            except yara.Error as e:
                self.skipped_rules.append({'file': full_path, 'error': str(e)})

        if not valid_files:
            return None

        try:
            compiled = yara.compile(filepaths=valid_files)
            self.loaded_rule_count = len(valid_files)
            return compiled
        except yara.Error as e:
            logger.warning("No se pudieron compilar las reglas YARA validadas individualmente: %s", e)
            return None

    def reload(self):
        """Vuelve a compilar las reglas (útil tras actualizar yara_rules/)."""
        self.skipped_rules = []
        self.loaded_rule_count = 0
        self.rules = self._compile_rules(self.rules_path) if yara else None

    def scan(self, file_path):
        """Escaneo con metadatos enriquecidos.

        Bug corregido (falso positivo): algunas reglas de la comunidad se
        marcan a sí mismas con meta 'hide: true' — es una convención donde
        el propio autor de la regla indica "esta es de baja confianza /
        muy ruidosa, no la muestres directamente al usuario final" (así
        estaba marcada, por ejemplo, la regla que confundió el encabezado
        estándar de un MP4 con JavaScript ofuscado). Antes se ignoraba esa
        bandera; ahora esas coincidencias se separan en 'low_confidence_matches'
        y NO cuentan para match_count/severity (que es lo que alimenta el
        score de riesgo), pero se conservan en el resultado por transparencia.
        """
        if yara is None:
            return {'error': 'yara-python no está instalado (pip install yara-python)'}
        if not self.rules:
            return {'error': f'No se encontraron reglas YARA compilables en "{self.rules_path}"'}

        try:
            matches = self.rules.match(file_path, timeout=self.timeout_seconds)
        except Exception as exc:
            return {
                'error': f'Error o timeout durante el análisis YARA: {exc}',
                'matches': [],
                'match_count': 0,
                'rules_loaded': self.loaded_rule_count,
                'rules_skipped': len(self.skipped_rules),
            }
        results = []
        low_confidence = []

        for match in matches:
            entry = {
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [self._format_string_match(s) for s in match.strings[:10]],
            }
            if self._meta_flag(match.meta.get('hide')):
                low_confidence.append(entry)
            else:
                results.append(entry)

        return {
            'matches': results,
            'match_count': len(results),
            'severity': self._calculate_severity(
                [m for m in matches if not self._meta_flag(m.meta.get('hide'))]),
            'low_confidence_matches': low_confidence,
            'low_confidence_count': len(low_confidence),
            'rules_loaded': self.loaded_rule_count,
            'rules_skipped': len(self.skipped_rules),
        }

    @staticmethod
    def _meta_flag(value):
        """Interpreta metadata YARA sin tratar el string "false" como True."""
        if isinstance(value, str):
            return value.strip().lower() in {'true', 'yes', '1'}
        return value is True or (isinstance(value, int) and not isinstance(value, bool) and value != 0)

    def _format_string_match(self, s):
        """Compatibilidad entre versiones de yara-python: >=4.3 devuelve
        objetos StringMatch (con .identifier/.instances), versiones viejas
        devuelven tuplas (offset, identifier, data). Bug real: el código
        original asumía siempre el formato de tupla y lanzaba
        `TypeError: 'yara.StringMatch' object is not subscriptable` con la
        versión de yara-python instalada."""
        try:
            identifier = s.identifier
            instances = s.instances
            if instances:
                data = instances[0].matched_data
                content = data.hex() if isinstance(data, bytes) else data
            else:
                content = None
        except AttributeError:
            _offset, identifier, data = s
            content = data.hex() if isinstance(data, bytes) else data
        return {'identifier': identifier, 'content': content}

    def _calculate_severity(self, matches):
        severity = 0
        for match in matches:
            if 'malware' in match.tags:
                severity += 3
            elif 'suspicious' in match.tags:
                severity += 2
            else:
                severity += 1
        return severity
