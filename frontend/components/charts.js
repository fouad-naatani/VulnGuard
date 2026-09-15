/**
 * Chart.js factories used across the dashboard and detail pages.
 * @module components/charts
 */
 
import { SEVERITY_COLORS, severityColor } from '../utils/format.js';
 
/** Apply the dark theme defaults to every chart. */
function applyDefaults() {
  const styles = getComputedStyle(document.documentElement);
  Chart.defaults.color = styles.getPropertyValue('--text-muted').trim() || '#94A3B8';
  Chart.defaults.borderColor = styles.getPropertyValue('--border').trim() || '#334155';
  Chart.defaults.font.family = '"Segoe UI", Roboto, Arial, sans-serif';
}
 
/**
 * Destroy any chart already bound to a canvas before re-rendering it.
 * @param {HTMLCanvasElement} canvas Target canvas.
 */
function reset(canvas) {
  const existing = Chart.getChart(canvas);
  if (existing) existing.destroy();
}
 
/**
 * Render the severity distribution doughnut.
 * @param {HTMLCanvasElement} canvas Target canvas.
 * @param {{labels: string[], values: number[]}} series Chart data.
 * @returns {Chart} The created chart.
 */
export function renderSeverityChart(canvas, series) {
  applyDefaults();
  reset(canvas);
  return new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: series.labels.map((label) => label.toUpperCase()),
      datasets: [
        {
          data: series.values,
          backgroundColor: series.labels.map((label) => severityColor(label)),
          borderWidth: 0,
          hoverOffset: 8,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 14 } } },
    },
  });
}
 
/**
 * Render the CVSS distribution histogram.
 * @param {HTMLCanvasElement} canvas Target canvas.
 * @param {{labels: string[], values: number[]}} series Chart data.
 * @returns {Chart} The created chart.
 */
export function renderCvssChart(canvas, series) {
  applyDefaults();
  reset(canvas);
  const palette = [
    SEVERITY_COLORS.low,
    SEVERITY_COLORS.low,
    SEVERITY_COLORS.medium,
    SEVERITY_COLORS.high,
    SEVERITY_COLORS.critical,
  ];
  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: series.labels,
      datasets: [
        {
          label: 'Findings',
          data: series.values,
          backgroundColor: series.labels.map((_, index) => palette[index % palette.length]),
          borderRadius: 8,
          maxBarThickness: 46,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}
 
/**
 * Render the monthly scan history line chart.
 * @param {HTMLCanvasElement} canvas Target canvas.
 * @param {{labels: string[], values: number[]}} series Chart data.
 * @returns {Chart} The created chart.
 */
export function renderMonthlyScansChart(canvas, series) {
  applyDefaults();
  reset(canvas);
  return new Chart(canvas, {
    type: 'line',
    data: {
      labels: series.labels,
      datasets: [
        {
          label: 'Scans',
          data: series.values,
          borderColor: '#2563EB',
          backgroundColor: 'rgba(37, 99, 235, 0.18)',
          fill: true,
          tension: 0.35,
          pointRadius: 4,
          pointBackgroundColor: '#2563EB',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}
 
/**
 * Render a CVSS gauge used on the vulnerability detail page.
 * @param {HTMLCanvasElement} canvas Target canvas.
 * @param {number} score CVSS base score between 0 and 10.
 * @returns {Chart} The created chart.
 */
export function renderCvssGauge(canvas, score) {
  applyDefaults();
  reset(canvas);
  const value = Math.max(0, Math.min(10, Number(score ?? 0)));
  const color =
    value >= 9
      ? SEVERITY_COLORS.critical
      : value >= 7
        ? SEVERITY_COLORS.high
        : value >= 4
          ? SEVERITY_COLORS.medium
          : SEVERITY_COLORS.low;
  return new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [
        {
          data: [value, 10 - value],
          backgroundColor: [color, 'rgba(148, 163, 184, 0.18)'],
          borderWidth: 0,
          circumference: 240,
          rotation: 240,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '76%',
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
    },
  });
}