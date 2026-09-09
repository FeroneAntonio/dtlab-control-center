"""Static Material Design 3 theme adapted to the DTLab product."""

from __future__ import annotations

import streamlit as st


def apply_theme() -> None:
    st.markdown(
        """
<style>
:root {
  --md-sys-color-primary:#006b5f;
  --md-sys-color-on-primary:#ffffff;
  --md-sys-color-primary-container:#9ef2df;
  --md-sys-color-on-primary-container:#00201b;
  --md-sys-color-secondary:#4b635d;
  --md-sys-color-secondary-container:#cde8df;
  --md-sys-color-tertiary:#416277;
  --md-sys-color-tertiary-container:#c8e6ff;
  --md-sys-color-on-tertiary-container:#001e2e;
  --md-sys-color-surface:#f7faf9;
  --md-sys-color-surface-container-lowest:#ffffff;
  --md-sys-color-surface-container-low:#f0f5f3;
  --md-sys-color-surface-container:#eaf0ee;
  --md-sys-color-surface-container-high:#e3ebe8;
  --md-sys-color-surface-container-highest:#dce5e2;
  --md-sys-color-on-surface:#17201e;
  --md-sys-color-on-surface-variant:#3f4946;
  --md-sys-color-outline:#6f7976;
  --md-sys-color-outline-variant:#bec9c5;
  --md-sys-color-error:#ba1a1a;
  --md-sys-color-error-container:#ffdad6;
  --md-sys-color-on-error-container:#410002;
  --dt-primary:var(--md-sys-color-primary);
  --dt-on-primary:var(--md-sys-color-on-primary);
  --dt-primary-container:var(--md-sys-color-primary-container);
  --dt-on-primary-container:var(--md-sys-color-on-primary-container);
  --dt-secondary:var(--md-sys-color-secondary);
  --dt-secondary-container:var(--md-sys-color-secondary-container);
  --dt-tertiary:var(--md-sys-color-tertiary);
  --dt-tertiary-container:var(--md-sys-color-tertiary-container);
  --dt-on-tertiary-container:var(--md-sys-color-on-tertiary-container);
  --dt-surface:var(--md-sys-color-surface);
  --dt-surface-low:var(--md-sys-color-surface-container-low);
  --dt-surface-high:var(--md-sys-color-surface-container-high);
  --dt-surface-highest:var(--md-sys-color-surface-container-highest);
  --dt-on-surface:var(--md-sys-color-on-surface);
  --dt-on-surface-variant:var(--md-sys-color-on-surface-variant);
  --dt-outline:var(--md-sys-color-outline);
  --dt-outline-variant:var(--md-sys-color-outline-variant);
  --dt-error:var(--md-sys-color-error);
  --dt-error-container:var(--md-sys-color-error-container);
  --dt-on-error-container:var(--md-sys-color-on-error-container);
  --dt-warning:#8a5100;
  --dt-info:#185abc;
  --dt-radius-s:12px;
  --dt-radius-m:20px;
  --dt-radius-l:28px;
}
html,body,[class*="css"] {
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}
[data-testid="stAppViewContainer"] {
  background:var(--dt-surface);
  color:var(--dt-on-surface);
}
[data-testid="stSidebar"] {
  background:#eef5f2;
  border-right:1px solid var(--dt-outline-variant);
}
[data-testid="stHeader"] {background:rgba(247,250,249,.94);}
.block-container {
  max-width:1540px;
  padding-top:1.25rem;
  padding-bottom:3rem;
}
h1,h2,h3 {
  color:var(--dt-on-surface);
  letter-spacing:-.025em;
}
h1 {font-size:clamp(1.8rem,3vw,2.7rem);}
h2 {font-size:1.3rem;margin-top:1.35rem;}
h3 {font-size:1rem;}
.dt-brand {
  padding:.55rem .2rem 1.05rem;
  border-bottom:1px solid var(--dt-outline-variant);
  margin-bottom:.8rem;
}
.dt-brand-mark {
  width:42px;height:42px;border-radius:14px;
  display:grid;place-items:center;
  background:var(--dt-primary);color:#fff;
  font-weight:800;letter-spacing:-.04em;
}
.dt-brand-title {font-weight:760;margin-top:.65rem;color:var(--dt-on-surface);}
.dt-brand-sub {font-size:.76rem;color:var(--dt-on-surface-variant);}
.dt-hero {
  padding:22px 24px;
  border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-l);
  background:linear-gradient(120deg,#fff 0%,#e8f7f2 62%,#d8efe8 100%);
  margin-bottom:18px;
}
.dt-eyebrow {
  color:var(--dt-primary);
  font-size:.72rem;font-weight:760;
  letter-spacing:.12em;text-transform:uppercase;
}
.dt-hero h1 {margin:4px 0 6px;}
.dt-hero p {
  color:var(--dt-on-surface-variant);
  max-width:960px;margin:0;
}
.dt-status-row {display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;}
.dt-chip {
  display:inline-flex;align-items:center;gap:7px;
  min-height:30px;padding:3px 11px;border-radius:999px;
  background:var(--dt-secondary-container);color:#17332c;
  font-size:.75rem;font-weight:680;
}
.dt-chip.real {background:#c5f6e8;color:#064f42;}
.dt-chip.observed {background:#d7eaff;color:#173f68;}
.dt-chip.expected {background:#f0e3ff;color:#563579;}
.dt-chip.demo {background:#ffe3b8;color:#5c3900;}
.dt-chip.unavailable,.dt-chip.stale {background:#e3e8e6;color:#48524f;}
.dt-chip.high {background:#ffd9d5;color:#8c1d18;}
.dt-chip.medium {background:#ffddb8;color:#5b3100;}
.dt-chip.low {background:#c5f6e8;color:#064f42;}
.dt-dot {width:8px;height:8px;border-radius:50%;background:currentColor;}
.dt-metric {
  min-height:132px;padding:18px;
  border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-m);
  background:#fff;box-shadow:0 1px 2px rgba(19,41,35,.04);
}
.dt-metric .label {
  color:var(--dt-on-surface-variant);
  font-size:.72rem;font-weight:680;
  text-transform:uppercase;letter-spacing:.06em;
}
.dt-metric .value {
  font-size:1.95rem;line-height:1.05;
  margin:9px 0 7px;font-weight:760;color:var(--dt-on-surface);
}
.dt-metric .meta {color:var(--dt-on-surface-variant);font-size:.78rem;}
.dt-live-strip {
  display:grid;grid-template-columns:1.2fr repeat(3,minmax(0,1fr));
  align-items:stretch;gap:1px;margin:0 0 16px;
  overflow:hidden;border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-m);background:var(--dt-outline-variant);
}
.dt-live-state,.dt-live-item {
  min-width:0;padding:13px 16px;background:var(--md-sys-color-surface-container-lowest);
}
.dt-live-state {display:flex;align-items:center;gap:11px;}
.dt-live-state>span:last-child {display:flex;min-width:0;flex-direction:column;}
.dt-live-state b,.dt-live-item b {
  overflow:hidden;color:var(--dt-on-surface);font-size:.88rem;
  line-height:1.25;text-overflow:ellipsis;white-space:nowrap;
}
.dt-live-state small,.dt-live-item small {
  color:var(--dt-on-surface-variant);font-size:.7rem;line-height:1.35;
}
.dt-live-item {display:flex;flex-direction:column;justify-content:center;gap:2px;}
.dt-live-pulse {
  width:10px;height:10px;flex:0 0 auto;border-radius:50%;
  background:var(--dt-primary);box-shadow:0 0 0 4px rgba(0,107,95,.13);
}
.dt-live-state.partial .dt-live-pulse,.dt-live-state.stale .dt-live-pulse {
  background:var(--dt-warning);box-shadow:0 0 0 4px rgba(138,81,0,.13);
}
.dt-live-state.offline .dt-live-pulse,.dt-live-state.failed .dt-live-pulse {
  background:var(--dt-error);box-shadow:0 0 0 4px rgba(186,26,26,.13);
}
.dt-security-topology {
  display:grid;grid-template-columns:1.05fr 1fr 1.15fr;gap:1px;
  margin:0 0 14px;overflow:hidden;border:1px solid #e6c29b;
  border-left:5px solid var(--dt-warning);border-radius:var(--dt-radius-m);
  background:#e6c29b;
}
.dt-security-identity,.dt-security-state,.dt-security-action {
  min-width:0;padding:15px 16px;background:var(--md-sys-color-surface-container-lowest);
}
.dt-security-identity {
  display:grid;grid-template-columns:auto 1fr;align-items:center;gap:12px;
  background:#fff8ef;
}
.dt-security-icon {
  display:grid;place-items:center;width:42px;height:42px;border-radius:14px;
  background:#ffddb8;color:var(--dt-warning);font-size:1.25rem;
}
.dt-security-topology small {
  display:block;color:var(--dt-on-surface-variant);font-size:.66rem;font-weight:750;
  letter-spacing:.065em;text-transform:uppercase;
}
.dt-security-topology strong {
  display:block;overflow:hidden;margin:5px 0 4px;color:var(--dt-on-surface);
  font-size:.9rem;line-height:1.3;text-overflow:ellipsis;
}
.dt-security-topology span {
  color:var(--dt-on-surface-variant);font-size:.71rem;line-height:1.4;
}
.dt-security-links {display:flex;flex-wrap:wrap;gap:0 12px;margin-top:5px;}
.dt-security-action a {
  display:inline-flex;align-items:center;min-height:44px;
  color:var(--dt-warning);font-size:.72rem;font-weight:760;text-decoration:none;
}
.dt-security-action a.primary {color:var(--dt-primary);}
.dt-security-action a:hover {text-decoration:underline;}
.dt-security-topology.communication_observed {
  border-color:var(--dt-warning);background:var(--dt-warning);
}
.dt-baseline-signal {
  display:grid;grid-template-columns:44px minmax(0,1fr);align-items:start;gap:14px;
  margin:0 0 16px;padding:16px 18px;border:1px solid #91b9d3;
  border-left:5px solid var(--dt-warning);border-radius:var(--dt-radius-m);
  background:var(--dt-tertiary-container);color:var(--dt-on-tertiary-container);
}
.dt-baseline-signal.unattributed {
  border-color:var(--dt-outline-variant);border-left-color:var(--dt-tertiary);
  background:var(--dt-surface-low);
}
.dt-baseline-icon {
  display:grid;place-items:center;width:44px;height:44px;border-radius:14px;
  background:var(--dt-tertiary);color:#fff;font-size:1.2rem;font-weight:800;
}
.dt-baseline-content {min-width:0;}
.dt-baseline-content>small {
  display:block;color:var(--dt-tertiary);font-size:.67rem;font-weight:780;
  letter-spacing:.07em;text-transform:uppercase;
}
.dt-baseline-content>strong {
  display:block;margin:4px 0;color:var(--dt-on-tertiary-container);
  font-size:1rem;line-height:1.35;
}
.dt-baseline-content>p {
  max-width:1050px;margin:0;color:var(--dt-on-surface-variant);
  font-size:.78rem;line-height:1.5;
}
.dt-evidence-pills {display:flex;flex-wrap:wrap;gap:7px;margin-top:10px;}
.dt-evidence-pill {
  display:inline-flex;align-items:center;min-height:30px;padding:3px 10px;
  border:1px solid rgba(65,98,119,.3);border-radius:999px;background:rgba(255,255,255,.62);
  color:var(--dt-on-tertiary-container);font-size:.69rem;font-weight:680;
}
.dt-security-topology.unavailable {
  border-color:var(--dt-outline-variant);border-left-color:var(--dt-outline);
  background:var(--dt-outline-variant);
}
.dt-kpi-grid {
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 16px;
}
.dt-cockpit-kpi {
  position:relative;min-width:0;min-height:136px;padding:16px;
  overflow:hidden;border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-m);background:var(--md-sys-color-surface-container-lowest);
}
.dt-cockpit-kpi::before {
  position:absolute;inset:0 auto 0 0;width:4px;background:var(--dt-outline);
  content:"";
}
.dt-cockpit-kpi.primary {background:#e8f7f2;}
.dt-cockpit-kpi.primary::before {background:var(--dt-primary);}
.dt-cockpit-kpi.attention {background:#fff5e7;}
.dt-cockpit-kpi.attention::before {background:var(--dt-warning);}
.dt-cockpit-kpi.quality {background:#edf4fa;}
.dt-cockpit-kpi.quality::before {background:var(--dt-tertiary);}
.dt-cockpit-kpi.workflow {background:#f1efff;}
.dt-cockpit-kpi.workflow::before {background:#65558f;}
.dt-cockpit-kpi span,.dt-infra-item span {
  display:block;color:var(--dt-on-surface-variant);font-size:.68rem;font-weight:720;
  letter-spacing:.055em;text-transform:uppercase;
}
.dt-cockpit-kpi strong {
  display:block;margin:12px 0 8px;color:var(--dt-on-surface);
  font-size:clamp(1.45rem,2.15vw,2rem);line-height:1;font-weight:760;
}
.dt-cockpit-kpi small,.dt-infra-item small {
  display:block;color:var(--dt-on-surface-variant);font-size:.73rem;line-height:1.35;
}
.dt-section-heading {
  display:flex;align-items:end;justify-content:space-between;gap:22px;margin:26px 0 10px;
}
.dt-section-heading.compact {margin-top:30px;}
.dt-section-heading span {
  color:var(--dt-primary);font-size:.68rem;font-weight:760;
  letter-spacing:.1em;text-transform:uppercase;
}
.dt-section-heading h2 {margin:2px 0 0;font-size:1.35rem;}
.dt-section-heading p {
  max-width:520px;margin:0;color:var(--dt-on-surface-variant);
  font-size:.78rem;text-align:right;
}
.dt-signal-summary {display:flex;flex-wrap:wrap;gap:7px;margin:0 0 10px;}
.dt-signal-summary span {
  padding:5px 10px;border-radius:999px;background:var(--dt-surface-high);
  color:var(--dt-on-surface-variant);font-size:.7rem;
}
.dt-signal-summary b {margin-left:3px;color:var(--dt-on-surface);}
.dt-journey {
  display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;
  margin:0 0 22px;padding:9px;border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-m);background:var(--dt-surface-low);
}
.dt-journey-step {
  position:relative;display:grid;grid-template-columns:auto 1fr;column-gap:9px;
  min-width:0;min-height:76px;padding:12px 13px;border-radius:14px;
  color:var(--dt-on-surface);text-decoration:none;background:#fff;
  transition:background-color .18s ease,box-shadow .18s ease,transform .18s ease;
}
.dt-journey-step>span {
  grid-row:1/3;display:grid;place-items:center;width:28px;height:28px;border-radius:50%;
  color:var(--dt-primary);font-size:.66rem;font-weight:780;background:var(--dt-primary-container);
}
.dt-journey-step>b {overflow:hidden;font-size:.83rem;text-overflow:ellipsis;white-space:nowrap;}
.dt-journey-step>small {
  overflow:hidden;color:var(--dt-on-surface-variant);font-size:.68rem;
  text-overflow:ellipsis;white-space:nowrap;
}
.dt-priority-card {
  min-height:214px;margin:7px 0;padding:16px 17px;
  border:1px solid var(--dt-outline-variant);border-left:5px solid var(--dt-outline);
  border-radius:var(--dt-radius-m);background:var(--md-sys-color-surface-container-lowest);
  transition:border-color .18s ease,box-shadow .18s ease,transform .18s ease;
}
.dt-priority-card.critical {border-left-color:var(--dt-error);}
.dt-priority-card.high {border-left-color:#d65f00;}
.dt-priority-card.medium {border-left-color:#c17a00;}
.dt-priority-card.low {border-left-color:#3f866f;}
.dt-priority-card.info {border-left-color:var(--dt-info);}
.dt-priority-head {display:flex;align-items:center;justify-content:space-between;gap:10px;}
.dt-priority-kind,.dt-priority-level {
  color:var(--dt-on-surface-variant);font-size:.65rem;font-weight:760;
  letter-spacing:.065em;text-transform:uppercase;
}
.dt-priority-level {
  padding:3px 8px;border-radius:999px;background:var(--dt-surface-high);
  letter-spacing:.035em;
}
.dt-priority-card.critical .dt-priority-level,.dt-priority-card.high .dt-priority-level {
  background:#ffdad6;color:#8c1d18;
}
.dt-priority-card.medium .dt-priority-level {background:#ffddb8;color:#5b3100;}
.dt-priority-card h3 {margin:10px 0 5px;font-size:1rem;line-height:1.3;}
.dt-priority-card p {
  min-height:2.6em;margin:0;color:var(--dt-on-surface-variant);
  font-size:.78rem;line-height:1.45;
}
.dt-priority-action {
  display:flex;flex-direction:column;gap:2px;margin-top:13px;padding:10px 11px;
  border-radius:12px;background:var(--dt-surface-low);
}
.dt-priority-action b {color:var(--dt-primary);font-size:.66rem;text-transform:uppercase;}
.dt-priority-action span {color:var(--dt-on-surface);font-size:.77rem;line-height:1.4;}
.dt-operational-meta {
  display:flex;flex-wrap:wrap;gap:5px 12px;margin-top:10px;color:var(--dt-on-surface-variant);
  font-size:.68rem;
}
.dt-operational-meta b {color:var(--dt-on-surface);font-weight:720;}
.dt-action-link {
  display:inline-flex;align-items:center;min-height:44px;margin-top:8px;padding:0 5px;
  border-radius:10px;color:var(--dt-primary);font-size:.76rem;font-weight:740;
  text-decoration:none;
}
.dt-action-link:hover {text-decoration:underline;}
.dt-infra-grid {
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 12px;
}
.dt-infra-item {
  min-width:0;padding:15px 16px;border-radius:16px;background:var(--dt-surface-low);
}
.dt-infra-item strong {
  display:block;overflow:hidden;margin:7px 0 4px;color:var(--dt-on-surface);
  font-size:1.03rem;line-height:1.25;text-overflow:ellipsis;white-space:nowrap;
}
.dt-panel {
  padding:18px 20px;border:1px solid var(--dt-outline-variant);
  border-radius:var(--dt-radius-m);background:#fff;margin:8px 0 14px;
}
.dt-empty {
  padding:28px;border:1px dashed var(--dt-outline);
  border-radius:var(--dt-radius-m);background:var(--dt-surface-low);
  text-align:center;color:var(--dt-on-surface-variant);
}
.dt-empty strong {display:block;color:var(--dt-on-surface);margin-bottom:5px;}
.dt-finding {
  padding:14px 16px;border-radius:16px;background:#fff;
  border:1px solid var(--dt-outline-variant);margin:8px 0;
}
.dt-finding.critical {border-left:5px solid var(--dt-error);}
.dt-finding.high {border-left:5px solid #d65f00;}
.dt-finding.medium {border-left:5px solid #c58a00;}
.dt-finding.low {border-left:5px solid #568a62;}
.dt-finding.info {border-left:5px solid var(--dt-info);}
.dt-finding .sev {
  font-size:.68rem;font-weight:760;text-transform:uppercase;
  letter-spacing:.08em;color:var(--dt-on-surface-variant);
}
.dt-finding .title {font-weight:720;margin:3px 0;}
.dt-finding .detail {color:var(--dt-on-surface-variant);font-size:.84rem;}
.dt-kicker {
  color:var(--dt-on-surface-variant);font-size:.78rem;
  margin:-.35rem 0 .75rem;
}
div[data-testid="stButton"] button,
div[data-testid="stDownloadButton"] button {
  border-radius:999px;min-height:44px;font-weight:650;
}
div[data-baseweb="select"]>div,
div[data-baseweb="input"]>div {min-height:44px;border-radius:14px;}
[data-testid="stAppViewContainer"] :focus-visible {
  outline:3px solid rgba(0,107,95,.42);outline-offset:2px;
}
[data-testid="stAppViewContainer"] button:focus-visible,
[data-testid="stAppViewContainer"] [role="button"]:focus-visible,
[data-testid="stAppViewContainer"] input:focus-visible {
  box-shadow:0 0 0 4px rgba(0,107,95,.15);
}
[data-testid="stDataFrame"] {
  border:1px solid var(--dt-outline-variant);
  border-radius:16px;overflow:hidden;
}
@media (hover:hover) {
  .dt-priority-card:hover {
    border-color:var(--dt-outline);box-shadow:0 7px 20px rgba(19,41,35,.08);
    transform:translateY(-1px);
  }
  .dt-journey-step:hover {
    background:var(--dt-primary-container);box-shadow:0 5px 15px rgba(19,41,35,.07);
    transform:translateY(-1px);
  }
}
@media (max-width:1450px) {
  .dt-kpi-grid {grid-template-columns:repeat(3,minmax(0,1fr));}
}
@media (max-width:1100px) {
  .dt-live-strip {grid-template-columns:repeat(2,minmax(0,1fr));}
  .dt-infra-grid {grid-template-columns:repeat(2,minmax(0,1fr));}
  .dt-journey {grid-template-columns:repeat(3,minmax(0,1fr));}
  .dt-security-topology {grid-template-columns:1fr 1fr;}
  .dt-security-action {grid-column:1/-1;}
}
@media (max-width:760px) {
  .block-container {padding:1.8rem .8rem 2rem;}
  .dt-hero {padding:18px;border-radius:22px;}
  .dt-metric {min-height:110px;}
  .dt-kpi-grid {grid-template-columns:repeat(2,minmax(0,1fr));}
  .dt-section-heading {align-items:start;flex-direction:column;gap:5px;}
  .dt-section-heading p {text-align:left;}
  .dt-priority-card {min-height:0;}
  .dt-journey {grid-template-columns:repeat(2,minmax(0,1fr));}
  .dt-security-topology {grid-template-columns:1fr;}
  .dt-security-action {grid-column:auto;}
  .dt-baseline-signal {grid-template-columns:38px minmax(0,1fr);padding:14px;}
  .dt-baseline-icon {width:38px;height:38px;border-radius:12px;}
}
@media (max-width:480px) {
  .dt-live-strip,.dt-kpi-grid,.dt-infra-grid,.dt-journey {grid-template-columns:1fr;}
  .dt-live-state,.dt-live-item {padding:12px 14px;}
  .dt-cockpit-kpi {min-height:118px;}
}
@media (prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    scroll-behavior:auto!important;transition-duration:.01ms!important;
    animation-duration:.01ms!important;animation-iteration-count:1!important;
  }
}
</style>
""",
        unsafe_allow_html=True,
    )
