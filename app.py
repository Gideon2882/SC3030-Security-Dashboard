"""SC3030 security-policy checker demo. Run with: python -m streamlit run app.py"""
import csv
import hashlib
import io
from pathlib import Path

import streamlit as st
from validator import POLICIES, EXPANDED_POLICIES, validate

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / 'samples'
EXPERIMENTS = ROOT / 'experiment_configs'

st.set_page_config(page_title='SC3030 | Network Configuration Security Validator',
                   page_icon='🛡️', layout='wide', initial_sidebar_state='expanded')
st.markdown('''
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 2.0rem; max-width: 1330px;}
.hero {background:linear-gradient(110deg,#13375b,#2369a0); padding:21px 28px;
       border-radius:15px; color:white; margin-bottom:20px;}
.hero h1 {font-size:2.05rem; margin:0; color:white; font-weight:800;}
.hero p {font-size:0.97rem; opacity:.93; margin:8px 0 0;}
.badge {display:inline-block; font-size:.8rem; background:rgba(255,255,255,.15);
        padding:4px 10px; border-radius:15px; margin-bottom:8px;}
.flow {border:1px solid rgba(130,150,165,.5); border-radius:10px;
       padding:12px; text-align:center; min-height:80px;}
.flow small {color:gray;}
.muted {font-size:.88rem;color:gray;}
</style>
''', unsafe_allow_html=True)

st.markdown('''<div class="hero"><span class="badge">SC3030 • Hands-on research demonstrator</span>
<h1>SC3030 Project Security Dashboard</h1>
<p>Independent policy checks for a limited subset of Cisco-style IPv4 ACL configurations.</p></div>''',
            unsafe_allow_html=True)

st.info('**Scope:** This is a deterministic, local static ACL evaluator—not Cisco IOS, a packet simulator, '
        'or proof of network security. The included examples are illustrative and **not measured LLM results**.')

with st.sidebar:
    st.markdown('### 🧪 Laboratory policy')
    st.caption('Single-router model, three directly connected /24 networks.')
    st.markdown('''**Guest:** `192.168.20.0/24`  
**Staff:** `192.168.10.0/24`  
**Server:** `10.0.0.0/24`''')
    test_set = st.radio('Policy suite',
        ['Original — 4 policies', 'Expanded — 8 policies'],
        index=1,
        help='Original preserves your previous results. Expanded adds 4 new, stricter checks.')
    policies = EXPANDED_POLICIES if test_set.startswith('Expanded') else POLICIES
    st.markdown(f'#### {len(policies)} specified expected outcomes')
    for p in policies:
        prefix = '🛡️' if p.group == 'Security' else '⚙️'
        st.markdown(f'{prefix} **{p.identifier}** — {p.name}  \nExpected: **{p.expected}**')
    st.divider()
    with st.expander('Technical scope and limitations'):
        st.markdown('''- Supports IPv4 `ip access-list extended NAME`, ordered `permit`/`deny`,
          `ip`/`tcp`/`udp`/`icmp`, `any`, `host`, wildcard masks, numeric `eq` destination ports,
          optional numbered entries, and `ip access-group NAME in/out`.
        - Models ACLs on directly connected routed interfaces only.
        - Does **not** model NAT, routing protocols, session state, interface admin status,
          device acceptance, physical operation, or comprehensive security.
        - Unrecognized ACL entries stop evaluation rather than silently permitting traffic.
        - Other non-ACL configuration commands are **not checked**.''')

st.markdown('#### Target network')
a, b, c, d = st.columns([1.1, 1.1, 1.1, 1.1], gap='small')
with a:
    st.markdown('<div class="flow">🖥️ <b>Guest</b><br><small>192.168.20.10</small></div>', unsafe_allow_html=True)
with b:
    st.markdown('<div class="flow">🖥️ <b>Staff</b><br><small>192.168.10.10</small></div>', unsafe_allow_html=True)
with c:
    st.markdown('<div class="flow">🖧 <b>Router R1</b><br><small>Ordered IPv4 ACLs</small></div>', unsafe_allow_html=True)
with d:
    st.markdown('<div class="flow">🗄️ <b>Server</b><br><small>10.0.0.10</small></div>', unsafe_allow_html=True)

st.markdown('### Step 1 — Load or paste a configuration')
st.caption('Choose a policy suite, load a sample, or paste/upload a Cisco IOS-style configuration. '
           'This dashboard validates text; it does not generate router configurations.')

if 'editor' not in st.session_state:
    st.session_state['editor'] = (SAMPLES / '01_unsafe_missing_deny.txt').read_text(encoding='utf-8')

col_a, col_b, col_c = st.columns(3)
for col, label, filename in [
    (col_a, 'Load unsafe example', '01_unsafe_missing_deny.txt'),
    (col_b, 'Load corrected example', '02_corrected.txt'),
    (col_c, 'Load overblocking example', '03_overblocked_dns.txt'),
]:
    with col:
        if st.button(label, use_container_width=True):
            st.session_state['editor'] = (SAMPLES / filename).read_text(encoding='utf-8')

st.markdown('##### Reproduce all four experiment configurations')
st.caption('Original A/B were generated for **4 requirements**; expanded A/B were freshly generated for **8 requirements**. '
           'Select **Expanded — 8 policies** on the left to reproduce the 5/8 and 8/8 results.')

def load_configuration(filename):
    st.session_state['editor'] = (EXPERIMENTS / filename).read_text(encoding='utf-8')

st.markdown('**Original — 4 requirements**')
orig_a, orig_b = st.columns(2)
with orig_a:
    if st.button('Load Original A', use_container_width=True):
        load_configuration('A_original_4_requirements.txt')
with orig_b:
    if st.button('Load Original B', use_container_width=True):
        load_configuration('B_original_4_requirements.txt')

st.markdown('**Expended — 8 requirements**')
new_a, new_b = st.columns(2)
with new_a:
    if st.button('Load Expended A', use_container_width=True):
        load_configuration('A_basic_8_requirements.txt')
with new_b:
    if st.button('Load Expended B', use_container_width=True):
        load_configuration('B_guided_8_requirements.txt')

with st.expander('Show reproducible comparison across both policy suites', expanded=False):
    comparison = []
    for label, filename in [
        ('Original A — 4 requirements','A_original_4_requirements.txt'),
        ('Original B — 4 requirements','B_original_4_requirements.txt'),
        ('New A — 8 requirements','A_basic_8_requirements.txt'),
        ('New B — 8 requirements','B_guided_8_requirements.txt'),
    ]:
        config = (EXPERIMENTS / filename).read_text(encoding='utf-8')
        result4 = validate(config, POLICIES)
        result8 = validate(config, EXPANDED_POLICIES)
        comparison.append((label, f"{result4['passed']}/4", f"{result8['passed']}/8"))
    lines = ['| Configuration | Original suite | Expanded suite |', '|---|:---:|:---:|']
    lines += [f'| {label} | {score4} | {score8} |' for label, score4, score8 in comparison]
    st.markdown('\n'.join(lines))
    st.caption('Computed from the exact included configuration files. Original configurations were **not** '
               'given the additional policies. The results illustrate test coverage, not a measured prompting improvement.')

uploaded = st.file_uploader('Or upload your own .txt/.cfg/.ios configuration',
                            type=['txt','cfg','ios'])
if uploaded is not None and st.button('Load uploaded configuration into editor'):
    try:
        st.session_state['editor'] = uploaded.getvalue().decode('utf-8')
    except UnicodeDecodeError:
        st.error('Please upload a UTF-8 text file.')

st.text_area('Router configuration (editable)', key='editor', height=255)

st.markdown('### Step 2 — Run independent policy checks')
run = st.button('🔍 Validate configuration', type='primary', use_container_width=True)
if run:
    with st.spinner(f'Evaluating ordered ACLs against {len(policies)} specified flows...'):
        st.session_state['last_report'] = validate(st.session_state['editor'], policies)
        st.session_state['last_hash'] = hashlib.sha256(st.session_state['editor'].encode()).hexdigest()
        st.session_state['last_suite'] = test_set

report = st.session_state.get('last_report')
current_hash = hashlib.sha256(st.session_state['editor'].encode()).hexdigest()
if report and (st.session_state.get('last_hash') != current_hash or st.session_state.get('last_suite') != test_set):
    st.warning('The configuration or selected policy suite changed. Click Validate configuration again.')
    report = None

if report:
    st.markdown('### Step 3 — Inspect evidence and results')
    if not report['valid_for_model']:
        st.error('❌ NOT EVALUATED: This configuration cannot be interpreted safely by the limited ACL model.')
        for msg in report['errors']:
            st.write('• ' + msg)
    else:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric('All policy tests', f"{report['passed']} / {report['total']}")
        m2.metric('Security', f"{report['security_passed']} / {sum(p.group == 'Security' for p in policies)}")
        m3.metric('Operational safety', f"{report['safety_passed']} / {sum(p.group == 'Operational safety' for p in policies)}")
        m4.metric('Result', 'PASS' if report['passed'] == report['total'] else 'FAIL')
        if report['passed'] == report['total']:
            st.success(f'✅ All {len(policies)} **specified** policy tests passed in this limited model.')
        else:
            st.error('❌ At least one specified policy test failed. Inspect the matching ACL rule below.')
        st.dataframe([{k: v for k,v in row.items() if k != 'Evidence'} for row in report['results']],
                     hide_index=True, use_container_width=True)
        with st.expander('Explain each observed result — matching ACL evidence', expanded=True):
            for row in report['results']:
                mark = '✅' if row['Status']=='PASS' else '❌'
                st.markdown(f"**{mark} {row['ID']}: {row['Policy']}** — expected `{row['Expected']}`, "
                            f"modeled `{row['Observed']}`")
                st.code(row['Evidence'], language='text')
        buff = io.StringIO()
        writer = csv.DictWriter(buff, fieldnames=report['results'][0].keys())
        writer.writeheader()
        writer.writerows(report['results'])
        st.download_button('Download test evidence (CSV)', buff.getvalue(),
                           file_name=('sc3030_expanded_8_results.csv' if test_set.startswith('Expanded') else 'sc3030_original_4_results.csv'), mime='text/csv')

st.divider()
st.caption('**Research limitations:** Original A/B were generated against 4 requirements, while new A/B were generated against 8. '
           'Compare configurations only under the same specified requirements and test suite. '
           'Sample inputs are illustrative; experiment inputs are preserved in experiment_configs/. '
           'These static ACL checks do not establish device acceptance or complete network security.')
