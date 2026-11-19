import { jsPDF } from "jspdf";

export function exportExecutiveMemoPdf(result) {
  if (!result) return;

  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 16;
  const maxW = pageW - margin * 2;
  let y = 0;

  const ensureSpace = (needed = 18) => {
    if (y + needed > 278) {
      doc.addPage();
      y = 18;
    }
  };

  // --- HEADER BANNER ---
  doc.setFillColor(11, 18, 32);
  doc.rect(0, 0, pageW, 32, "F");
  doc.setFillColor(134, 188, 37);
  doc.rect(0, 32, pageW, 2, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(17);
  doc.text("DealShield AI  |  Note de Synthèse Due Diligence M&A", margin, 15);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  doc.setTextColor(180, 198, 220);
  const dateStr = new Date().toLocaleDateString("fr-FR", {
    day: "2-digit",
    month: "long",
    year: "numeric",
  });
  doc.text(
    `Deloitte x Google Cloud  •  Date : ${dateStr}  •  Profil RBAC : ${result.user_role.toUpperCase()}  •  Moteur : ${result.mode}`,
    margin,
    24
  );

  y = 44;

  // --- KPI SUMMARY BOX ---
  doc.setFillColor(244, 247, 252);
  doc.setDrawColor(210, 220, 235);
  doc.roundedRect(margin, y, maxW, 20, 3, 3, "FD");

  const kpis = [
    { label: "Documents", val: String(result.documents_scanned) },
    { label: "Score Menace", val: `${result.overall_threat_score}/100` },
    { label: "Attaques Bloquées", val: String(result.injections_blocked) },
    { label: "DLP / RBAC", val: String(result.pii_redacted) },
    { label: "Red Flags", val: String(result.red_flags.length) },
  ];
  const colW = maxW / kpis.length;
  kpis.forEach((k, idx) => {
    const x = margin + idx * colW + 5;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(95, 110, 130);
    doc.text(k.label, x, y + 7);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text(k.val, x, y + 15);
  });

  y += 29;

  // --- SECTION 1: RED FLAGS ---
  const drawSectionTitle = (title) => {
    ensureSpace(16);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12.5);
    doc.setTextColor(15, 23, 42);
    doc.text(title, margin, y);
    doc.setDrawColor(134, 188, 37);
    doc.setLineWidth(0.6);
    doc.line(margin, y + 2, margin + 45, y + 2);
    y += 9;
  };

  drawSectionTitle("1. Points d'Alerte Majeurs (Red Flags M&A)");

  result.red_flags.forEach((rf) => {
    ensureSpace(28);
    const isCrit = rf.severity === "Critique";
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.setTextColor(isCrit ? 185 : 180, isCrit ? 28 : 105, isCrit ? 28 : 10);
    doc.text(`[${rf.severity.toUpperCase()}]`, margin, y);

    doc.setTextColor(15, 23, 42);
    const titleLines = doc.splitTextToSize(`${rf.id} — ${rf.title}`, maxW - 28);
    doc.text(titleLines, margin + 24, y);
    y += titleLines.length * 4.8;

    doc.setFont("helvetica", "italic");
    doc.setFontSize(8.5);
    doc.setTextColor(90, 105, 125);
    const impactTxt = rf.financial_impact_eur
      ? `  •  Impact estimé : ${rf.financial_impact_eur.toLocaleString("fr-FR")} EUR`
      : "";
    doc.text(`Source : ${rf.doc_name} (${rf.page})${impactTxt}`, margin + 4, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.2);
    doc.setTextColor(40, 50, 65);
    const descLines = doc.splitTextToSize(rf.description, maxW - 4);
    doc.text(descLines, margin + 4, y);
    y += descLines.length * 4.4 + 1;

    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    doc.setTextColor(75, 85, 99);
    const exLines = doc.splitTextToSize(`Preuve : ${rf.excerpt}`, maxW - 6);
    doc.text(exLines, margin + 4, y);
    y += exLines.length * 3.8 + 5;
  });

  // --- SECTION 2: FINANCIAL CHECKS ---
  drawSectionTitle("2. Contrôles Financiers Déterministes");

  if (result.financial_checks.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(90, 105, 125);
    doc.text("Aucun ratio financier structuré détecté sur ce périmètre.", margin, y);
    y += 8;
  } else {
    result.financial_checks.forEach((fc) => {
      ensureSpace(18);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9.8);
      doc.setTextColor(fc.status === "ALERT" ? 185 : 15, fc.status === "ALERT" ? 28 : 23, 42);
      doc.text(`[${fc.status}] ${fc.metric} : ${fc.computed_value}`, margin, y);
      y += 4.8;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(60, 72, 90);
      const lines = doc.splitTextToSize(`${fc.threshold_or_expected} — ${fc.explanation}`, maxW - 4);
      doc.text(lines, margin + 4, y);
      y += lines.length * 4.4 + 4;
    });
  }

  // --- SECTION 3: CYBER SHIELD ---
  drawSectionTitle("3. Journal du Bouclier Cyber & Conformité DLP");
  if (result.security_events.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(40, 50, 65);
    doc.text("Aucune menace ou fuite de données détectée.", margin, y);
    y += 8;
  } else {
    result.security_events.forEach((ev) => {
      ensureSpace(14);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text(`• ${ev.event_type} (${ev.doc_name})`, margin, y);
      y += 4.4;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.8);
      doc.setTextColor(65, 75, 90);
      const evLines = doc.splitTextToSize(ev.details, maxW - 6);
      doc.text(evLines, margin + 4, y);
      y += evLines.length * 4.2 + 3;
    });
  }

  // --- SECTION 4: RECOMMENDATION ---
  ensureSpace(26);
  drawSectionTitle("4. Recommandation Deloitte Transaction Services");
  const hasCrit = result.red_flags.some((r) => r.severity === "Critique");
  const recText = hasCrit
    ? "Ajustement de prix et/ou Garantie d'Actif et de Passif (GAP) fortement recommandés avant signature pour couvrir la dépendance client (Change of Control) et les engagements hors-bilan identifiés."
    : "Aucun point de blocage critique identifié sur le périmètre analysé.";

  doc.setFillColor(240, 249, 232);
  doc.setDrawColor(134, 188, 37);
  const recLines = doc.splitTextToSize(recText, maxW - 10);
  const boxH = recLines.length * 5 + 8;
  doc.roundedRect(margin, y, maxW, boxH, 2.5, 2.5, "FD");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9.5);
  doc.setTextColor(25, 45, 10);
  doc.text(recLines, margin + 5, y + 6.5);

  // Page numbers
  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(140, 150, 165);
    doc.text(
      `DealShield AI — Document confidentiel généré pour Deloitte M&A  |  Page ${p}/${totalPages}`,
      margin,
      290
    );
  }

  doc.save("Note_Synthese_Due_Diligence_DealShield.pdf");
}
