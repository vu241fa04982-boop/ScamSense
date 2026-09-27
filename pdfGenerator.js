/**
 * ScamSense Client-Side PDF Report Generator
 * Uses jsPDF to generate and download a clean, professional, multi-page aware PDF report.
 */

import { jsPDF } from 'jspdf';
import { CATEGORY_DETAILS } from './analyzer.js';

export function downloadAnalysisPDF(analysis) {
  if (!analysis) return;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 16;
  const contentWidth = pageWidth - (margin * 2);
  let y = 18;

  function checkPageBreak(neededHeight) {
    if (y + neededHeight > pageHeight - 20) {
      doc.addPage();
      y = 18;
      // Add subtle header on continuation pages
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(140, 140, 140);
      doc.text('SCAMSENSE — Message Safety Analysis Report (continued)', margin, 10);
      doc.setDrawColor(230, 230, 230);
      doc.line(margin, 12, pageWidth - margin, 12);
      return true;
    }
    return false;
  }

  // --- BRAND HEADER ---
  doc.setFillColor(234, 88, 12); // #EA580C Primary Orange
  doc.rect(margin, y, 4, 14, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(234, 88, 12);
  doc.text('SCAMSENSE', margin + 7, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(100, 50, 30);
  doc.text('Message Safety Analysis Report', margin + 7, y + 12);

  // Date formatted
  const analysisDate = analysis.timestamp ? new Date(analysis.timestamp) : new Date();
  const dateStr = analysisDate.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(120, 120, 120);
  doc.text(dateStr, pageWidth - margin, y + 6, { align: 'right' });

  y += 20;

  // --- SUMMARY META BOX ---
  doc.setFillColor(255, 247, 237); // #FFF7ED
  doc.setDrawColor(253, 186, 116); // #FDBA74
  doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'FD');

  // Risk Level
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(124, 45, 18);
  doc.text('RISK LEVEL', margin + 6, y + 7);

  doc.setFontSize(13);
  if (analysis.level === 'HIGH') {
    doc.setTextColor(220, 38, 38);
  } else if (analysis.level === 'MODERATE') {
    doc.setTextColor(217, 119, 6);
  } else {
    doc.setTextColor(5, 150, 105);
  }
  doc.text(analysis.level || 'REVIEW', margin + 6, y + 15);

  // Status Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(124, 45, 18);
  doc.text('STATUS', margin + 50, y + 7);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(67, 20, 7);
  doc.text(analysis.levelTitle || 'WARNING SIGNS FOUND', margin + 50, y + 15);

  // Warning Signs Count
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(124, 45, 18);
  doc.text('WARNING SIGNS', pageWidth - margin - 35, y + 7);

  doc.setFontSize(13);
  doc.setTextColor(234, 88, 12);
  doc.text(`${analysis.warningSignCount || 0} Found`, pageWidth - margin - 35, y + 15);

  y += 28;

  // --- ORIGINAL MESSAGE SECTION ---
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(67, 20, 7);
  doc.text('ORIGINAL MESSAGE', margin, y);
  y += 5;

  const originalLines = doc.splitTextToSize(analysis.originalText || '(No text provided)', contentWidth - 10);
  const msgBoxHeight = Math.max(14, (originalLines.length * 4.8) + 8);

  checkPageBreak(msgBoxHeight + 8);
  doc.setFillColor(250, 250, 250);
  doc.setDrawColor(220, 220, 220);
  doc.roundedRect(margin, y, contentWidth, msgBoxHeight, 2, 2, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(50, 50, 50);
  doc.text(originalLines, margin + 5, y + 6);

  y += msgBoxHeight + 10;

  // --- WARNING SIGNS FOUND SECTION ---
  checkPageBreak(25);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(67, 20, 7);
  doc.text(`DETECTED WARNING SIGNS (${analysis.findings ? analysis.findings.length : 0})`, margin, y);
  y += 6;

  if (!analysis.findings || analysis.findings.length === 0) {
    checkPageBreak(16);
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(187, 247, 208);
    doc.roundedRect(margin, y, contentWidth, 14, 2, 2, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(22, 101, 52);
    doc.text('No obvious warning patterns were flagged in this message snippet.', margin + 5, y + 8);
    y += 20;
  } else {
    analysis.findings.forEach((finding, idx) => {
      const catDetail = CATEGORY_DETAILS[finding.category] || {};
      const title = finding.title || 'Warning Pattern';
      const excerpt = finding.matchedText ? `"${finding.matchedText}"` : '';
      
      const whyLines = doc.splitTextToSize(`Why it matters: ${finding.whyItMatters || catDetail.description || ''}`, contentWidth - 12);
      const actionLines = doc.splitTextToSize(`What to do: ${finding.whatToDo || catDetail.advice || ''}`, contentWidth - 12);

      const cardHeight = 14 + (excerpt ? 6 : 0) + (whyLines.length * 4.2) + (actionLines.length * 4.2) + 6;

      checkPageBreak(cardHeight + 4);

      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(245, 158, 11);
      doc.roundedRect(margin, y, contentWidth, cardHeight, 2, 2, 'D');

      // Left orange accent indicator
      doc.setFillColor(234, 88, 12);
      doc.rect(margin, y, 2.5, cardHeight, 'F');

      let innerY = y + 6;

      // Card Title
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(234, 88, 12);
      doc.text(`${idx + 1}. ${title}`, margin + 6, innerY);

      // Badge label
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(catDetail.badge || 'Risk Indicator', pageWidth - margin - 4, innerY, { align: 'right' });

      innerY += 6;

      // Excerpt if present
      if (excerpt) {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(8.5);
        doc.setTextColor(90, 90, 90);
        doc.text(excerpt, margin + 6, innerY);
        innerY += 5.5;
      }

      // Why it matters
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(60, 60, 60);
      doc.text(whyLines, margin + 6, innerY);
      innerY += (whyLines.length * 4.2) + 2;

      // What to do
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(20, 80, 50);
      doc.text(actionLines, margin + 6, innerY);

      y += cardHeight + 5;
    });
  }

  // --- RECOMMENDED ACTIONS CHECKLIST ---
  if (analysis.actionList && analysis.actionList.length > 0) {
    checkPageBreak(25);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(67, 20, 7);
    doc.text('RECOMMENDED SAFETY ACTIONS', margin, y);
    y += 6;

    analysis.actionList.forEach((act, idx) => {
      const actionText = `${idx + 1}. ${act.title}: ${act.detail}`;
      const actionLines = doc.splitTextToSize(actionText, contentWidth - 10);
      const rowHeight = (actionLines.length * 4.2) + 4;

      checkPageBreak(rowHeight + 2);

      doc.setFillColor(255, 251, 247);
      doc.setDrawColor(254, 215, 170);
      doc.roundedRect(margin, y, contentWidth, rowHeight, 1.5, 1.5, 'FD');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(67, 20, 7);
      doc.text(actionLines, margin + 4, y + 4.5);

      y += rowHeight + 3;
    });
    y += 4;
  }

  // --- FINAL SAFETY SUMMARY ---
  checkPageBreak(25);
  doc.setFillColor(255, 247, 237);
  doc.setDrawColor(234, 88, 12);
  doc.roundedRect(margin, y, contentWidth, 18, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(234, 88, 12);
  doc.text('IMPORTANT SAFETY SUMMARY', margin + 5, y + 5.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 50, 30);
  const noticeLines = doc.splitTextToSize(
    'ScamSense is an educational awareness tool designed to identify patterns to review. It does not definitively confirm fraud or safety. Always verify unexpected communications using official contact information from your billing statement or bookmarked apps.',
    contentWidth - 10
  );
  doc.text(noticeLines, margin + 5, y + 10.5);

  // Filename format: ScamSense-Analysis-YYYY-MM-DD.pdf
  const dateFormatted = analysisDate.toISOString().split('T')[0];
  const filename = `ScamSense-Analysis-${dateFormatted}.pdf`;

  // Download directly to device
  doc.save(filename);
}
