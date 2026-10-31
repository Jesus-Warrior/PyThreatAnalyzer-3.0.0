"""
Detector local basado en heurísticas + modelo ML opcional.

Bugs corregidos:
  - numpy/scikit-learn opcionales (ver _NUMPY_AVAILABLE/_SKLEARN_AVAILABLE):
    si faltan, el heurístico (Python puro, collections.Counter) sigue
    funcionando en vez de tumbar la app entera al arrancar.
  - Memory exhaustion: extract_features() leía el archivo COMPLETO en
    memoria sin límite. Un archivo de 2GB podía causar MemoryError. Ahora,
    archivos >50MB se muestrean (header + bloque medio + cola, 1MB cada
    uno) igual que ya hace virus_analyzer.py para entropía/strings — así
    ambos módulos usan el mismo criterio de "qué es un archivo grande".
  - Los modelos pickle/joblib externos se rechazan: deserializarlos puede
    ejecutar código. Para modelos ML se admite .skops con validación de tipos;
    si el formato seguro no está disponible, continúa el análisis heurístico.
"""

import os
import logging
from collections import Counter
import math
import stat
import re
import hashlib
import hmac

try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

from analysis_utils import (
    LARGE_FILE_THRESHOLD, SAMPLE_CHUNK_SIZE, is_high_entropy_expected,
)

logger = logging.getLogger('PyThreatAnalyzer')

# Alias conservado para consumidores existentes; la fuente común vive en
# analysis_utils.py.
MAX_FULL_READ_SIZE = LARGE_FILE_THRESHOLD

# Tipos internos generados por el RandomForest entrenado en este proyecto.
# La allowlist es intencionalmente por tipo exacto: no confiar en todo el
# resultado de get_untrusted_types(), ni en namespaces completos.
# sklearn.tree._tree.Tree es la estructura Cython de cada árbol del bosque.
# Las versiones de sklearn/skops no están fijadas: si un cambio agrega otro
# tipo, la carga se bloquea hasta revisar y aprobar explícitamente ese tipo.
SKOPS_TRUSTED_TYPE_ALLOWLIST = frozenset({
    'sklearn.tree._tree.Tree',
})


def _is_inside(path, base):
    """Comprueba contención tras resolver symlinks; evita startswith()."""
    try:
        real = os.path.realpath(path)
        base_real = os.path.realpath(base)
        return os.path.normcase(os.path.commonpath([real, base_real])) == os.path.normcase(base_real)
    except (OSError, ValueError):
        return False


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class MLDetector:
    def __init__(self, model_path=None, trusted_model_sha256=None):
        self.model = None
        self.feature_names = None
        self.trusted_model_sha256 = trusted_model_sha256
        if model_path and os.path.exists(model_path):
            try:
                self.load_model(model_path)
            except Exception as exc:
                # Un modelo opcional inválido no debe impedir iniciar la GUI;
                # se conserva el detector heurístico sin cargar pickle.
                logger.warning(
                    f"No se cargó el modelo ML '{model_path}': {exc}. "
                    "Se usará el detector heurístico."
                )

    # ---------- Extracción de características (funciona sin numpy) ----------
    def extract_features(self, file_path):
        if not stat.S_ISREG(os.stat(file_path).st_mode):
            raise ValueError("La extracción de características solo admite archivos regulares")
        size = os.path.getsize(file_path)

        if size > MAX_FULL_READ_SIZE:
            with open(file_path, 'rb') as f:
                header = f.read(SAMPLE_CHUNK_SIZE)
                f.seek(size // 2)
                middle = f.read(SAMPLE_CHUNK_SIZE)
                f.seek(max(0, size - SAMPLE_CHUNK_SIZE))
                tail = f.read(SAMPLE_CHUNK_SIZE)
                data = header + middle + tail
                sampled = True
        else:
            with open(file_path, 'rb') as f:
                data = f.read()
                sampled = False

        if not data:
            return {
                'size': size, 'entropy': 0.0, 'printable_ratio': 0.0,
                'has_mz': False, 'has_elf': False, 'max_byte_freq': 0.0,
                'sampled': sampled,
            }

        entropy = self._calculate_entropy(data)
        printable = sum(1 for b in data if 32 <= b <= 126)

        if _NUMPY_AVAILABLE:
            byte_counts = np.bincount(bytearray(data), minlength=256)
            max_byte_freq = float(byte_counts.max()) / len(data)
        else:
            counts = Counter(data)
            max_byte_freq = max(counts.values()) / len(data)

        return {
            'size': size,
            'entropy': entropy,
            'printable_ratio': printable / len(data),
            'has_mz': data[:2] == b'MZ',
            'has_elf': data[:4] == b'\x7fELF',
            'max_byte_freq': max_byte_freq,
            'sampled': sampled,
        }

    def _calculate_entropy(self, data):
        """Entropía de Shannon. Con numpy es más rápida en archivos grandes;
        sin numpy, Counter (Python puro) da exactamente el mismo resultado."""
        if not data:
            return 0.0
        if _NUMPY_AVAILABLE:
            counts = np.bincount(bytearray(data), minlength=256)
            probs = counts[counts > 0] / len(data)
            return float(-(probs * np.log2(probs)).sum())
        else:
            counts = Counter(data)
            length = len(data)
            entropy = 0.0
            for count in counts.values():
                p_x = count / length
                entropy -= p_x * math.log2(p_x)
            return entropy

    # ---------- Predicción ----------
    def predict(self, file_path):
        features = self.extract_features(file_path)

        if self.model is not None and self.feature_names is not None and _NUMPY_AVAILABLE:
            try:
                # Solo pasamos al modelo las features que conoce (excluye
                # 'sampled', que es metadata añadida después de entrenar
                # modelos existentes y no forma parte del vector de entrenamiento).
                vector = np.array([[features[k] for k in self.feature_names]])
                prediction = self.model.predict(vector)[0]
                probability = self.model.predict_proba(vector)[0]
                return {
                    'method': 'ml_model',
                    'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                    'confidence': float(max(probability)),
                    'features': features,
                }
            except Exception:
                # Si el modelo falla por cualquier motivo, no rompemos el
                # análisis: caemos al heurístico.
                pass

        return self._heuristic_predict(features, file_path)

    def _heuristic_predict(self, features, file_path=None):
        """Puntuación heurística usable sin ningún dataset de entrenamiento
        NI numpy/scikit-learn instalados — es el modo por defecto de la app.

        Bug corregido (falso positivo sistémico): antes CUALQUIER archivo
        con entropía >7.5 se marcaba SOSPECHOSO, sin importar el formato.
        Pero video, audio, imágenes, ZIP y Office moderno ya vienen
        comprimidos/codificados por diseño — entropía ~8.0 es lo NORMAL en
        esos formatos, no un indicio de empaquetado/cifrado malicioso (eso
        solo es una señal fuerte en ejecutables: .exe/.dll/.sys). Ahora se
        consulta is_high_entropy_expected() para no penalizar esos casos.
        """
        score = 0
        reasons = []
        expected = is_high_entropy_expected(file_path) if file_path else False

        if features['entropy'] > 7.5:
            if expected:
                reasons.append(
                    f"Entropía alta ({features['entropy']:.2f}) pero esperada para este tipo de "
                    "archivo (formato ya comprimido/codificado) — no se pondera como sospechosa")
            else:
                score += 3
                reasons.append(f"Entropía muy alta ({features['entropy']:.2f}) - posible empaquetado/cifrado")
        elif features['entropy'] > 7.0 and not expected:
            score += 1
            reasons.append(f"Entropía elevada ({features['entropy']:.2f})")

        if features['printable_ratio'] < 0.1 and features['size'] > 100:
            score += 1
            reasons.append("Muy baja proporción de caracteres imprimibles")

        if features['max_byte_freq'] > 0.5:
            score += 1
            reasons.append("Distribución de bytes anómala (posible padding/relleno)")

        confidence = round(min(0.5 + score * 0.12, 0.95), 2)

        return {
            'method': 'heuristic',
            'prediction': 'SOSPECHOSO' if score >= 2 else 'BENIGNO',
            'confidence': confidence,
            'score': score,
            'reasons': reasons,
            'features': features,
        }

    # ---------- Entrenamiento / persistencia (requiere numpy + scikit-learn) ----------
    def train(self, samples, labels):
        """Entrena un RandomForest con archivos de muestra etiquetados (0=benigno, 1=malicioso).
        Requiere numpy y scikit-learn instalados (ver requirements.txt)."""
        if not (_NUMPY_AVAILABLE and _SKLEARN_AVAILABLE):
            raise ImportError(
                "Entrenar un modelo ML requiere numpy y scikit-learn. Instala con: "
                "uv pip install numpy scikit-learn (o pip install numpy scikit-learn)"
            )

        X, feature_names = [], None
        for sample in samples:
            feats = self.extract_features(sample)
            # 'sampled' es metadata informativa, no una característica numérica
            # útil para el modelo — se excluye del vector de entrenamiento.
            feats = {k: v for k, v in feats.items() if k != 'sampled'}
            if feature_names is None:
                feature_names = list(feats.keys())
            X.append([feats[k] for k in feature_names])

        self.feature_names = feature_names
        self.model = RandomForestClassifier(n_estimators=200, random_state=42)
        self.model.fit(np.array(X), labels)

    def save_model(self, path):
        if not self.model:
            raise ValueError("No hay modelo entrenado para guardar")
        try:
            import skops.io as sio
        except ImportError as exc:
            raise ImportError(
                "Guardar modelos de forma segura requiere 'skops' "
                "(instala el paquete skops)."
            ) from exc
        if not str(path).lower().endswith('.skops'):
            raise ValueError("El modelo seguro debe usar la extensión .skops")
        output_dir = os.path.dirname(os.path.abspath(os.fspath(path)))
        os.makedirs(output_dir, exist_ok=True)
        sio.dump({'model': self.model, 'feature_names': self.feature_names}, path)

    def load_model(self, path):
        """Carga solo el formato skops y rechaza tipos no confiables.

        Los modelos pickle/joblib pueden ejecutar código durante la carga y
        por eso no se aceptan, aunque estén configurados localmente.
        """
        if not _NUMPY_AVAILABLE:
            raise RuntimeError("numpy no está instalado; se usará el detector heurístico")
        if not str(path).lower().endswith('.skops'):
            raise ValueError(
                "Formato de modelo rechazado por seguridad. Los archivos pickle/joblib "
                "pueden ejecutar código y no se convierten automáticamente; vuelve a "
                "entrenar y guarda el resultado como .skops."
            )
        if not os.path.isfile(path) or os.path.getsize(path) > 256 * 1024 * 1024:
            raise ValueError("El modelo debe ser un archivo regular de hasta 256 MiB")
        project_dir = os.path.dirname(os.path.realpath(__file__))
        if not _is_inside(path, project_dir):
            expected_hash = self.trusted_model_sha256
            if not isinstance(expected_hash, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_hash):
                raise ValueError(
                    "Modelo externo rechazado: configura trusted_ml_model_sha256 con un SHA-256 "
                    "verificado por un canal autenticado"
                )
            actual_hash = _file_sha256(path)
            if not hmac.compare_digest(actual_hash.lower(), expected_hash.lower()):
                raise ValueError("El SHA-256 del modelo externo no coincide con el valor confiable")
        try:
            import skops.io as sio
        except ImportError as exc:
            raise ImportError("Para cargar modelos .skops instala el paquete 'skops'") from exc
        untrusted_types = sio.get_untrusted_types(file=path)
        unexpected_types = set(untrusted_types) - SKOPS_TRUSTED_TYPE_ALLOWLIST
        if unexpected_types:
            raise ValueError(
                "El modelo contiene tipos fuera de la allowlist y no se cargó: "
                + ', '.join(sorted(unexpected_types))
            )
        # skops solo recibe los tipos exactos que este modelo necesita y que
        # fueron revisados; cualquier tipo nuevo o inesperado se rechaza arriba.
        data = sio.load(path, trusted=sorted(set(untrusted_types)))
        if not isinstance(data, dict) or 'model' not in data or 'feature_names' not in data:
            raise ValueError("El contenido del modelo seguro no tiene el formato esperado")
        model = data['model']
        feature_names = data['feature_names']
        if not _SKLEARN_AVAILABLE or not isinstance(model, RandomForestClassifier):
            raise ValueError("El modelo debe ser un RandomForestClassifier")
        if (not isinstance(feature_names, list) or not feature_names or
                len(feature_names) > 4096 or not all(isinstance(name, str) for name in feature_names)):
            raise ValueError("Lista de características inválida en el modelo")
        estimators = getattr(model, 'estimators_', None)
        if not estimators or len(estimators) > 1000:
            raise ValueError("Cantidad de árboles fuera de límites")
        if getattr(model, 'n_features_in_', None) != len(feature_names):
            raise ValueError("La dimensión del modelo no coincide con sus características")

        # skops valida tipos, pero la allowlist de Tree también requiere
        # comprobar invariantes estructurales antes de permitir predict().
        total_nodes = 0
        for estimator in estimators:
            tree = getattr(estimator, 'tree_', None)
            if tree is None or tree.node_count < 1:
                raise ValueError("Árbol sin estructura válida")
            total_nodes += int(tree.node_count)
            if total_nodes > 1_000_000:
                raise ValueError("El bosque supera el límite de nodos permitido")
            left = tree.children_left
            right = tree.children_right
            features = tree.feature
            thresholds = tree.threshold
            if not (len(left) == len(right) == len(features) == len(thresholds) == tree.node_count):
                raise ValueError("Longitudes inconsistentes en la estructura del árbol")
            if (np.any(left < -1) or np.any(right < -1) or
                    np.any(left >= tree.node_count) or np.any(right >= tree.node_count)):
                raise ValueError("Índice de nodo fuera de rango en el árbol")
            for index, (left_child, right_child) in enumerate(zip(left, right)):
                leaf = left_child == -1 and right_child == -1
                if (left_child == -1) != (right_child == -1):
                    raise ValueError("Nodo con un solo hijo")
                if not leaf:
                    if left_child <= index or right_child <= index:
                        raise ValueError("Referencia de hijo cíclica o inválida")
                    if features[index] < 0 or features[index] >= len(feature_names):
                        raise ValueError("Índice de característica fuera de rango")
                    if not np.isfinite(thresholds[index]):
                        raise ValueError("Umbral no finito en el árbol")
            if not np.isfinite(tree.value).all():
                raise ValueError("Valores no finitos en el árbol")

        self.model = model
        self.feature_names = feature_names
        
