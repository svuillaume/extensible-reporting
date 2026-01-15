import pandas as pd
import plotly.graph_objects as go
from logzero import logger
import json


class HostVulnerabilities:

    def __init__(self, raw_data):
        # Filter Critical to CVSS score 10.0 only, keep all High/Medium/Low
        self.data = self._filter_by_severity_and_cvss(raw_data)

    def _filter_by_severity_and_cvss(self, raw_data):
        """Filter vulnerabilities: Critical must have CVSS 10.0, keep all High/Medium/Low.

        Args:
            raw_data: List of vulnerability records

        Returns:
            Filtered list of vulnerabilities
        """
        filtered_data = []
        critical_before = 0
        critical_after = 0

        for vuln in raw_data:
            severity = vuln.get('severity', '')

            # Keep all High, Medium, Low vulnerabilities
            if severity in ['High', 'Medium', 'Low']:
                filtered_data.append(vuln)
                continue

            # For Critical, only keep if CVSS score is 10.0
            if severity == 'Critical':
                critical_before += 1
                cvss_score = None

                # Try to extract CVSS score from various possible locations
                if 'cveProps' in vuln and vuln['cveProps']:
                    cve_props = vuln['cveProps']
                    if 'metadata' in cve_props and cve_props['metadata']:
                        metadata = cve_props['metadata']
                        if 'NVD' in metadata and metadata['NVD']:
                            nvd = metadata['NVD']
                            if 'CVSSv3' in nvd and nvd['CVSSv3']:
                                cvss_v3 = nvd['CVSSv3']
                                if 'Score' in cvss_v3:
                                    cvss_score = float(cvss_v3['Score'])

                    # Also check for cvssV3Score directly in cveProps
                    if cvss_score is None and 'cvssV3Score' in cve_props:
                        cvss_score = float(cve_props['cvssV3Score'])

                    # Check for cvss_v3_score
                    if cvss_score is None and 'cvss_v3_score' in cve_props:
                        cvss_score = float(cve_props['cvss_v3_score'])

                # Check top-level fields
                if cvss_score is None and 'cvssScore' in vuln:
                    cvss_score = float(vuln['cvssScore'])

                if cvss_score is None and 'cvss_score' in vuln:
                    cvss_score = float(vuln['cvss_score'])

                # Only include Critical if CVSS score is 10.0
                if cvss_score is not None and cvss_score >= 10.0:
                    filtered_data.append(vuln)
                    critical_after += 1

        logger.info(f'Filtered vulnerabilities: {len(raw_data)} total')
        logger.info(f'  Critical: {critical_before} -> {critical_after} (CVSS >= 10.0)')
        logger.info(f'  High/Medium/Low: kept all')
        logger.info(f'  Final count: {len(filtered_data)}')
        return filtered_data

    def total_evaluated(self):
        df = pd.DataFrame(self.data)
        # count severities by host & total sum
        unique_hosts = df.mid.nunique()
        return unique_hosts

    def summary_by_host(self, severities=("Critical", "High", "Medium", "Low"), limit=False):
        df = pd.json_normalize(self.data,
                               meta=[['cveProps', 'metadata'], ['evalCtx', 'hostname'], ['featureKey', 'name'],
                                     'vulnId', 'severity', 'mid'])

        if 'severity' not in df:
            df['severity'] = False

        # filter
        df = df[df['severity'].isin(severities)]

        # delete extra columns
        df = df[['evalCtx.hostname', 'mid', 'severity']]

        # count severities by MID
        df = df.groupby(['mid', 'severity', 'evalCtx.hostname']).size().reset_index(name='count')

        # summarize severities onto one column (and sort)
        df['sev_merged'] = df['severity'].astype('string') + ": " + df['count'].astype('string')
        df['severity'] = pd.Categorical(df['severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['severity', 'count'], ascending=[True, False])
        df = df.groupby('mid', sort=False, as_index=False).agg(
            {'mid': 'first', 'evalCtx.hostname': 'first', 'sev_merged': f"\n".join})

        # clean names
        df.rename(columns={'mid': 'Machine ID', 'evalCtx.hostname': 'Hostname', 'sev_merged': 'Severity Count'},
                  inplace=True)
        df = df.drop(columns=['Machine ID'])

        if limit:
            df = df.head(limit)
        return df

    def fixable_vulns(self, severities=("Critical", "High"), limit=False):
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'],
                                     ['featureKey', 'name'],
                                     'vulnId',
                                     'severity',
                                     ['fixInfo', 'fix_available'],
                                     ['fixInfo', 'fixed_version'],
                                     ['featureKey', 'version_installed']])
        if 'severity' not in df:
            df['severity'] = False
        df = df[df['severity'].isin(severities)]
        df = df[df['fixInfo.fix_available'] == '1']
        if not df.empty:
            #cve_count = df.groupby('evalCtx.hostname')['vulnId'].nunique()
            #print(cve_count)
            df = df[['evalCtx.hostname', 'severity', 'vulnId', 'featureKey.name', 'featureKey.version_installed', 'fixInfo.fixed_version']]
            # df = df.groupby(['evalCtx.hostname', 'featureKey.name', 'featureKey.version_installed', 'severity', 'vulnId'],
            #                 as_index=False).agg({'fixInfo.fixed_version': ', '.join})
            df = df.groupby(['evalCtx.hostname', 'severity', 'vulnId', 'featureKey.name', 'featureKey.version_installed'],
                            as_index=False).agg(lambda x: ', '.join(x.unique()) if x.dtype == 'object' else x.iloc[0])
            df = df.groupby(['evalCtx.hostname', 'severity', 'featureKey.name', 'fixInfo.fixed_version','featureKey.version_installed' ], as_index=False).agg({'vulnId': ', '.join})
            # rename columns
            df.rename(columns={'evalCtx.hostname': 'Hostname',
                               'severity': 'Severity',
                               'vulnId': 'CVE',
                               'featureKey.name': 'Package Name',
                               "fixInfo.fixed_version": "Fixed Version(s)",
                               'featureKey.version_installed': "Installed Version"},
                      inplace=True)
            df = df[['Hostname', 'CVE', 'Severity', 'Package Name', 'Installed Version', 'Fixed Version(s)']]
        return df

    def summary(self, severities=("Critical", "High", "Medium", "Low")):
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'], ['featureKey', 'name'], 'vulnId', 'severity', 'mid'])

        if 'severity' not in df:
            df['severity'] = False

        # filter
        df = df[df['severity'].isin(severities)]

        # delete extra columns
        df = df[['evalCtx.hostname', 'mid', 'severity']]

        # count severities by host & total sum
        df = df.groupby(['severity'], as_index=False)['mid'].agg(['count', 'nunique'])

        for severity in severities:
            if not severity in df.index: df = pd.concat(
                [df, pd.DataFrame([{'severity': severity, 'count': 0, 'nunique': 0}]).set_index('severity')])

        df = df.reset_index()

        # sort
        df['severity'] = pd.Categorical(df['severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['severity'])
        df = df.reset_index()
        df = df.drop(columns=['index'])

        # rename columns
        df.rename(columns={'severity': 'Severity', 'count': 'Total CVEs', 'nunique': 'Hosts Affected'}, inplace=True)

        return df

    def all_cves_detail(self, severities=("High", "Medium", "Low"), limit=100):
        """Get detailed CVE information for specified severities.

        Args:
            severities: Tuple of severity levels to include
            limit: Maximum number of CVEs to return

        Returns:
            DataFrame with CVE details
        """
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'],
                                     ['featureKey', 'name'],
                                     'vulnId',
                                     'severity',
                                     ['fixInfo', 'fix_available'],
                                     ['fixInfo', 'fixed_version'],
                                     ['featureKey', 'version_installed']])

        if 'severity' not in df:
            df['severity'] = False

        # Filter by severity
        df = df[df['severity'].isin(severities)]

        if df.empty:
            return df

        # Clean up column names
        df.rename(columns={
            'evalCtx.hostname': 'Hostname',
            'vulnId': 'CVE',
            'severity': 'Severity',
            'featureKey.name': 'Package Name',
            'featureKey.version_installed': 'Installed Version',
            'fixInfo.fix_available': 'Fix Available',
            'fixInfo.fixed_version': 'Fixed Version(s)'
        }, inplace=True)

        # Sort by severity then CVE
        df['Severity'] = pd.Categorical(df['Severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['Severity', 'CVE'])

        # Select and reorder columns
        columns_to_keep = ['Severity', 'CVE', 'Hostname', 'Package Name', 'Installed Version']
        if 'Fix Available' in df.columns and 'Fixed Version(s)' in df.columns:
            columns_to_keep.extend(['Fix Available', 'Fixed Version(s)'])

        df = df[columns_to_keep]

        if limit:
            df = df.head(limit)

        return df

    def host_vulns_by_severity_bar(self, severities=["Critical", "High", "Medium", "Low"], width=600, height=350, format='svg'):
        df = self.summary(severities=severities)

        # Modern gradient-inspired color palette with better contrast
        colors = [
            '#DC2626',  # Modern red for Critical
            '#F97316',  # Vibrant orange for High
            '#FBBF24',  # Warm yellow for Medium
            '#3B82F6'   # Clean blue for Low
        ]

        # Create bar chart with modern styling
        fig = go.Figure(data=[go.Bar(
            x=df['Severity'],
            y=df['Total CVEs'],
            marker=dict(
                color=colors,
                line=dict(color='rgba(255, 255, 255, 0.8)', width=1.5),
                opacity=0.9
            ),
            text=df['Total CVEs'],
            textposition='outside',
            textfont=dict(size=12, color='#1F2937', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
            hovertemplate='<b>%{x}</b><br>CVE Count: %{y}<extra></extra>'
        )])

        fig.update_layout(
            title=dict(
                text='Host Vulnerabilities by Severity',
                font=dict(size=18, color='#111827', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', weight=600),
                x=0.5,
                xanchor='center'
            ),
            yaxis=dict(
                title='Number of CVEs',
                titlefont=dict(size=14, color='#4B5563', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                tickfont=dict(size=12, color='#6B7280'),
                gridcolor='#E5E7EB',
                gridwidth=1,
                showgrid=True,
                zeroline=False
            ),
            xaxis=dict(
                titlefont=dict(size=14, color='#4B5563', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                tickfont=dict(size=12, color='#6B7280'),
                showgrid=False
            ),
            plot_bgcolor='rgba(249, 250, 251, 0.5)',
            paper_bgcolor='white',
            margin=dict(l=60, r=40, t=100, b=60),
            font=dict(family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
            hoverlabel=dict(
                bgcolor='white',
                font_size=13,
                font_family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                bordercolor='#E5E7EB'
            ),
            uniformtext=dict(mode='hide', minsize=8)
        )

        img_bytes = fig.to_image(format=format, width=width, height=height)
        return img_bytes