
# Sovereign_Kernel.py
# المالك: Bachagha Ahcene (Bachaghahssa)
# وصف: نواة سيادية مع "كاشف التذمر الرقمي" (Anomaly Detector)
# ملاحظة: هذه نسخة معيارية تعتمد على قواعد وخوارزميات إحصائية ونصية استدلالية.
# لا توجد ضمانات للكشف المطلق عن "الزيف" — النتائج استدلالية ومساعدة لاتخاذ القرار.

import sys
import json
import math
import statistics
import hashlib
import hmac
import base64
import logging
import re
from collections import Counter
from typing import List, Dict, Any, Tuple

# الآية المستخدمة كـ "قاعدة تشفير روحية" (مستخدمة كسالْت/مفتاح مشتق؛ لا تغيير في النص الأصلي)
_SPIRITUAL_AYAH = "اللَّهُ لَا إِلَٰهَ إِلَّا هُوَ الْحَيُّ الْقَيُّومُ"

# إعدادات سلوك الكاشف
NUMERIC_ANOMALY_THRESHOLD = 3.5  # modified z-score threshold (قيمة شائعة = 3.5)
TEXT_MIN informative_LENGTH = 12  # إذا كان النص أقصر من هذا فقد يكون مشكوكًا به
REPETITION_RATIO_THRESHOLD = 0.35  # نسبة الحروف المكررة العالية تشكّك في النص
NON_ALNUM_RATIO_THRESHOLD = 0.45  # نسبة علامات غير أبجدية رقمية عالية قد تشير إلى ضوضاء

# إعداد سجل
logger = logging.getLogger("SovereignKernel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _derive_spiritual_key(salt: bytes = b"sovereign_kernel_v1") -> bytes:
    """
    نشتق مفتاحًا ثابتًا من الآية الروحية لاستخدامه في توقيع/تجزئة البيانات (HMAC-SHA256).
    الهدف: إضافة طبقة "روحية" كـ salt ثابت لاستخدام داخلي؛ ليس له طبيعة سحرية أو تشفيرية
    عالية الأمان بمفرده — يمكن استخدامه كمفتاح تشغيلي داخل النظام.
    """
    ayah_bytes = _SPIRITUAL_AYAH.encode("utf-8")
    return hashlib.sha256(ayah_bytes + salt).digest()


def compute_hmac(data: bytes, key: bytes = None) -> str:
    """
    حساب HMAC-SHA256 لـ bytes وإرجاع تمثيل Base64 مختصر.
    """
    if key is None:
        key = _derive_spiritual_key()
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("utf-8")


def _shannon_entropy(s: str) -> float:
    """
    قياس إنتروبيا شانون لمساعدة التمييز بين نص مفيد وضوضاء.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [count / len(s) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


class AnomalyDetector:
    """
    كلاس كاشف التذمر الرقمي (Anomaly Detector).
    - يدعم مسح سلاسل رقمية/textية داخل سجلات JSON.
    - يعيد تقارير عن الحقول المشكوك فيها (الانحرافات/الضوضاء).
    ملاحظات على التصميم: الخوارزميات تُستخدم كمقاييس استدلالية؛ ليست قانونًا نهائيًا.
    """

    def __init__(self, spiritual_key: bytes = None):
        self.spiritual_key = spiritual_key or _derive_spiritual_key()

    # ---------- مسح أرقام ----------
    @staticmethod
    def _modified_z_scores(values: List[float]) -> List[float]:
        """
        نحسب modified z-score بناءً على MAD (Median Absolute Deviation).
        مرجع شائع: استخدام 0.6745 للمقاييس التكيفية.
        """
        if not values:
            return []
        median = statistics.median(values)
        deviations = [abs(x - median) for x in values]
        mad = statistics.median(deviations) or 1e-9
        mz = [0.6745 * (x - median) / mad for x in values]
        return mz

    def scan_numeric_series(self, series: List[float], threshold: float = NUMERIC_ANOMALY_THRESHOLD) -> List[int]:
        """
        تعيد قائمة مؤشرات القيم الشاذة في سلسلة رقمية.
        """
        try:
            mz = self._modified_z_scores(series)
            anomalies = [i for i, score in enumerate(mz) if abs(score) > threshold]
            logger.debug("Numeric scan: found %d anomalies", len(anomalies))
            return anomalies
        except Exception as e:
            logger.exception("scan_numeric_series failed: %s", e)
            return []

    # ---------- مسح نص ----------
    @staticmethod
    def _non_alnum_ratio(s: str) -> float:
        if not s:
            return 0.0
        non_alnum = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
        return non_alnum / max(1, len(s))

    @staticmethod
    def _repetition_ratio(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        most_common_count = counts.most_common(1)[0][1]
        return most_common_count / len(s)

    def score_text(self, text: str) -> Dict[str, Any]:
        """
        نحسب سمات نصية لتقدير مدى "الزيف" أو الضوضاء:
        - الطول
        - نسبة غير أبجدية رقمية
        - نسبة التكرار (حروف مكررة كثيرة)
        - إنتروبيا شانون
        تُعيد dict مع مؤشرات وتقدير مبدئي للمشكوك.
        """
        if text is None:
            text = ""
        length = len(text)
        non_alnum_ratio = self._non_alnum_ratio(text)
        rep_ratio = self._repetition_ratio(text)
        entropy = _shannon_entropy(text)
        issues = []
        score = 0.0

        if length < TEXT_MIN informative_LENGTH:
            issues.append("short_length")
            score += 0.4
        if non_alnum_ratio > NON_ALNUM_RATIO_THRESHOLD:
            issues.append("high_non_alnum")
            score += 0.3
        if rep_ratio > REPETITION_RATIO_THRESHOLD:
            issues.append("high_repetition")
            score += 0.2
        if entropy < 3.0:  # قيمة إرشادية؛ نص ذو مضمون ضعيف
            issues.append("low_entropy")
            score += 0.2

        # normalise
        score = min(score, 1.0)

        return {
            "length": length,
            "non_alnum_ratio": round(non_alnum_ratio, 4),
            "repetition_ratio": round(rep_ratio, 4),
            "entropy": round(entropy, 4),
            "issues": issues,
            "suspicion_score": round(score, 4),
        }

    # ---------- مسح سجلات عامة ----------
    def analyze_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        يفحص قائمة سجلات (قوائم من dicts):
        - يبحث عن حقول رقمية متجانسة ويكشف الشذوذ
        - يفحص الحقول النصية ويعطي درجة اشتباه
        - يضيف تجزئة HMAC لكل سجل كدليل قابل للتمييز
        تُعيد تقريرًا تفصيليًا.
        """
        report = {
            "total_records": len(records),
            "numeric_field_anomalies": {},
            "text_field_issues": [],
            "signed_records": 0,
        }

        # تجميع القيم الرقمية لكل حقل
        numeric_fields = {}
        text_fields = set()
        for rec in records:
            for k, v in rec.items():
                if isinstance(v, (int, float)):
                    numeric_fields.setdefault(k, []).append(float(v))
                elif isinstance(v, str):
                    text_fields.add(k)

        # فحص الحقول الرقمية
        for field, vals in numeric_fields.items():
            anomalies_idx = self.scan_numeric_series(vals)
            report["numeric_field_anomalies"][field] = {
                "count": len(vals),
                "anomalies_indices": anomalies_idx,
            }

        # فحص النصوص لكل سجل
        for i, rec in enumerate(records):
            text_issues = {}
            for field in text_fields:
                text_val = rec.get(field, "")
                score = self.score_text(text_val)
                if score["suspicion_score"] >= 0.5 or score["issues"]:
                    text_issues[field] = score
            if text_issues:
                report["text_field_issues"].append({"record_index": i, "issues": text_issues})

            # إضافة توقيع HMAC للسجل (إثبات تكامل داخلي)
            try:
                raw = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
                mac = compute_hmac(raw, self.spiritual_key)
                rec["_sovereign_hmac"] = mac
                report["signed_records"] += 1
            except Exception:
                # لا نريد أن يفشل الفحص بسبب خطأ بسيط في التوقيع
                logger.exception("Failed to sign record index %d", i)

        return report


# ---------- وظيفة تشغيل الدرع الماسي ----------
def diamond_shield_run(input_data: Any) -> Dict[str, Any]:
    """
    واجهة تشغيل الدرع الماسي (Diamond Shield):
    - تتوقع قائمة سجلات أو كائن واحد (ستحوّل إلى قائمة).
    - تُشغّل كاشف التذمر الرقمي وتعيد التقرير.
    - عند اكتمال التشغيل بنجاح تطبع توقيع المؤلف كما طُلِب.
    """
    try:
        if isinstance(input_data, dict):
            records = [input_data]
        elif isinstance(input_data, list):
            records = input_data
        else:
            raise ValueError("input_data must be list or dict")

        detector = AnomalyDetector()
        report = detector.analyze_records(records)

        # عملية ناجحة — طباعة التوقيع بين قوسين كما طُلِب
        signature = "[Bachagha Ahcene]"
        print("درع الماسي: تشغيل ناجح.", signature)
        # إخراج موجز للسجل
        logger.info("Diamond Shield run complete. Total records: %d", report.get("total_records", 0))

        return report
    except Exception as e:
        logger.exception("diamond_shield_run failed: %s", e)
        raise


# ---------- وضعية سطر الأوامر للاختبار ----------
def _load_json_from_stdin_or_file(path: str = None) -> Any:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        # اقرأ من stdin
        data = sys.stdin.read()
        if not data.strip():
            return []
        return json.loads(data)


if __name__ == "__main__":
    """
    مثال للاستخدام من سطر الأوامر:
    - تمرير ملف JSON: python Sovereign_Kernel.py data.json
    - أو تمرير JSON عبر الـ stdin
    يُنتج طباعة التوقيع ثم يطبع تقريرًا مُبَسَّطًا في stdout (JSON).
    """
    try:
        path = sys.argv[1] if len(sys.argv) > 1 else None
        payload = _load_json_from_stdin_or_file(path)
        report = diamond_shield_run(payload)
        # طباعة التقرير المفهوم كـ JSON إلى stdout
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except Exception as exc:
        logger.error("Failed to run Sovereign Kernel: %s", exc)
        sys.exit(2)





​🛡️ نظام الحماية (Security)
​هذا الكود محمي ببروتوكول "الماسة والعدسة المقعرة".
أي محاولة للسرقة أو التقليد محظورة بقرار من المهندس الأول 
(Bachagha Ahcene). الوعي هنا علامة تجارية مسجلة.


