import pandas as pd

import plotly.graph_objects as go
from logzero import logger


def process_compliance_violations(violations):
    output_string = ''
    for violation in violations:
        formatted_string = f"Region:{violation['region']}" + '\n' + f"Resource: {violation['resource']}" + '\n' + f"Reasons: {violation['reasons']}" + '\n\n'
        output_string += formatted_string
    return output_string
class Compliance:

    def __init__(self, data: dict):
        self.cloud_provider = data['cloud_provider']
        self.report_type = data['report_type']
        self.reports = data['reports']
        self.all_recommendations = self.get_all_recommendations()
        if self.cloud_provider == 'AWS':
            self.account_id_string = 'ACCOUNT_ID'
            self.account_id_rename_string = 'Account ID'
        if self.cloud_provider == 'AZURE':
            self.account_id_string = 'TENANT_ID'
            self.account_id_rename_string = 'Tenant ID'
        if self.cloud_provider == 'GCP':
            self.account_id_string = 'PROJECT_ID'
            self.account_id_rename_string = 'Project ID'

    def get_all_recommendations(self):
        results = []
        for entry in self.reports:
            report_type = entry['reportType']
            for recommendation in entry['recommendations']:
                results.append({**{'reportType': report_type}, **recommendation})
        return results

    def get_total_accounts_evaluated(self):
        df = pd.DataFrame(self.all_recommendations)
        unique_accounts = df[self.account_id_string].nunique()
        return unique_accounts

    def get_compliance_details(self, severities=["Critical", "High"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])

        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df = df.reset_index()

        df['Resources'] = df['RESOURCE_COUNT'].astype('string') + " / " + df['ASSESSED_RESOURCE_COUNT'].astype('string')

        df = df[[self.account_id_string, 'CATEGORY', 'TITLE', 'SEVERITY', 'Resources']]
        df.rename(columns={self.account_id_string: self.account_id_rename_string, 'CATEGORY': 'Category',
                           'TITLE': 'Title', 'SEVERITY': 'Severity'},
                  inplace=True)

        return df

    def critical_compliance_details(self):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df[df['SEVERITY'] == 1]
        df = df[[self.account_id_string, 'CATEGORY', 'TITLE', 'VIOLATIONS']]
        df.rename(columns={self.account_id_string: self.account_id_rename_string,
                           'CATEGORY': 'Category',
                           'TITLE': 'Control',
                           'VIOLATIONS': 'Violations'}, inplace=True)
        df['Violations'] = df['Violations'].apply(process_compliance_violations)

        return df

    def get_compliance_summary(self, severities=["Critical", "High"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]

        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])

        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df = df.groupby([self.account_id_string, 'SEVERITY']).agg(count=('SEVERITY', 'count'),
                                                        resources=('RESOURCE_COUNT', 'sum'),
                                                        assessed=('ASSESSED_RESOURCE_COUNT',
                                                                  'sum')).reset_index()  # .size().reset_index(name='count')
        df['sev_merged'] = df['SEVERITY'].astype('string') + ": " + df['count'].astype('string')

        df = df.groupby(self.account_id_string).agg(
            {'sev_merged': f"\n".join, 'resources': 'sum', 'assessed': 'sum'}).reset_index()
        df.rename(
            columns={self.account_id_string: self.account_id_rename_string, 'sev_merged': 'Severity Count',
                     'resources': 'Non-compliant Resources','assessed': 'Total Assessed Resources'},
            inplace=True)


        return df

    def get_summary_by_account(self, severities=["Critical", "High", "Medium", "Low"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())
        # sort to determine account order, while we still have the severity & resource count data
        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])
        account_order = df[self.account_id_string].unique()


        # group
        df = df.groupby([self.account_id_string, 'SEVERITY']).agg(failed_control_count=('SEVERITY', 'count'),
                                                        failed_resources=('RESOURCE_COUNT', 'sum')).reset_index()

        # sort by accounts with most criticals, followed by most highs
        df[self.account_id_string] = pd.Categorical(df[self.account_id_string], account_order)
        df.sort_values(by=[self.account_id_string, 'SEVERITY'], ascending=True)

        # convert int and filter severities
        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        # rename
        df.rename(
            columns={self.account_id_string: self.account_id_rename_string, 'SEVERITY': 'Severity', 'failed_resources': 'Non-compliant Resources',
                     'failed_control_count': 'Failed controls'}, inplace=True)

        # pivot and preseve severity order (pivot breaks this)
        severity_order = df['Severity'].unique()
        df = pd.pivot_table(df, values='Non-compliant Resources', index=self.account_id_rename_string, columns='Severity', sort=False)
        df = df.reindex(severity_order, axis=1)

        return df

    def get_summary_by_service(self, severities=["Critical", "High", "Medium", "Low"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.reset_index()

        df = df[[self.account_id_string, 'CATEGORY', 'SEVERITY', 'RESOURCE_COUNT']]

        # group by acct id, category
        df = df.groupby([self.account_id_string, 'CATEGORY']).agg(count=('RESOURCE_COUNT', 'sum')).reset_index()

        # determine category order
        df_category_order = df.groupby(['CATEGORY']).agg(count=('count', 'sum')).reset_index()
        df_category_order.sort_values('count', ascending=False, inplace=True)
        df_category_order = df_category_order['CATEGORY'].unique()
        df = df.astype({'CATEGORY': pd.CategoricalDtype(df_category_order, ordered=True)})

        # create pivot table
        df = pd.pivot_table(df, values='count', index=self.account_id_string, columns='CATEGORY', sort=False)
        return df

    def get_summary_by_account_bar_graph(self, width=600, height=350, format='svg'):
        df = self.get_summary_by_account()
        # Modern color palette matching severity levels
        colors = [
            '#DC2626',  # Modern red for Critical
            '#F97316',  # Vibrant orange for High
            '#FBBF24',  # Warm yellow for Medium
            '#3B82F6',  # Clean blue for Low
            '#6B7280'   # Gray for Info
        ]
        unique_accounts = len(df.index)

        if unique_accounts == 1:
            fig = go.Figure(go.Bar(
                x=df.columns,
                y=df.iloc[0],
                marker=dict(
                    color=colors[:len(df.columns)],
                    line=dict(color='rgba(255, 255, 255, 0.8)', width=1.5),
                    opacity=0.9
                ),
                text=df.iloc[0],
                textposition='outside',
                textfont=dict(size=12, color='#1F2937', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                hovertemplate='<b>%{x}</b><br>Failed Resources: %{y}<extra></extra>'
            ))
            fig.update_layout(
                title=dict(
                    text='Compliance Findings by Severity',
                    font=dict(size=18, color='#111827', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', weight=600),
                    x=0.5,
                    xanchor='center'
                ),
                yaxis=dict(
                    title='Failed Resources',
                    titlefont=dict(size=14, color='#4B5563', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                    tickfont=dict(size=12, color='#6B7280'),
                    gridcolor='#E5E7EB',
                    gridwidth=1,
                    showgrid=True,
                    zeroline=False
                ),
                xaxis=dict(
                    tickfont=dict(size=12, color='#6B7280', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                    showgrid=False
                ),
                plot_bgcolor='rgba(249, 250, 251, 0.5)',
                paper_bgcolor='white',
                margin=dict(l=60, r=40, t=100, b=60),
                font=dict(family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                uniformtext=dict(mode='hide', minsize=8)
            )
        else:
            severities = df.columns
            graph_data = []

            for idx, sev in enumerate(severities):
                bar = go.Bar(
                    name=sev,
                    x=df.index,
                    y=df[sev],
                    marker=dict(
                        color=colors[idx] if idx < len(colors) else colors[-1],
                        line=dict(color='rgba(255, 255, 255, 0.6)', width=1),
                        opacity=0.9
                    ),
                    text=df[sev],
                    textposition='inside',
                    textfont=dict(size=11, color='white', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                    hovertemplate='<b>%{x}</b><br>' + sev + ': %{y}<extra></extra>'
                )
                graph_data.append(bar)

            fig = go.Figure(data=graph_data[::-1])

            fig.update_layout(
                title=dict(
                    text='Compliance Findings by Account',
                    font=dict(size=18, color='#111827', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', weight=600),
                    x=0.5,
                    xanchor='center'
                ),
                yaxis=dict(
                    title='Failed Resources',
                    titlefont=dict(size=14, color='#4B5563', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                    tickfont=dict(size=12, color='#6B7280'),
                    gridcolor='#E5E7EB',
                    gridwidth=1,
                    showgrid=True,
                    zeroline=False
                ),
                xaxis=dict(
                    tickfont=dict(size=12, color='#6B7280', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                    showgrid=False
                ),
                barmode='stack',
                plot_bgcolor='rgba(249, 250, 251, 0.5)',
                paper_bgcolor='white',
                margin=dict(l=60, r=40, t=120, b=60),
                font=dict(family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                legend=dict(
                    orientation='h',
                    yanchor='bottom',
                    y=1.02,
                    xanchor='center',
                    x=0.5,
                    bgcolor='rgba(255, 255, 255, 0.8)',
                    bordercolor='#E5E7EB',
                    borderwidth=1,
                    font=dict(size=12, color='#374151')
                ),
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

    def get_summary_by_service_bar_graph(self, width=600, height=350, format='svg'):
        df = self.get_summary_by_service()

        # Modern color palette for accounts/tenants/projects
        account_colors = [
            '#0EA5E9', '#8B5CF6', '#EC4899', '#F59E0B', '#10B981',
            '#6366F1', '#F97316', '#14B8A6', '#EF4444', '#8B5CF6'
        ]

        categories = df.columns
        graph_data = []

        for idx, (acct, data) in enumerate(df.iterrows()):
            bar = go.Bar(
                name=acct,
                x=categories,
                y=data,
                marker=dict(
                    color=account_colors[idx % len(account_colors)],
                    line=dict(color='rgba(255, 255, 255, 0.6)', width=1),
                    opacity=0.9
                ),
                text=data,
                textposition='outside',
                textfont=dict(size=10, color='#1F2937', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                hovertemplate='<b>' + str(acct) + '</b><br>%{x}<br>Failed Resources: %{y}<extra></extra>'
            )
            graph_data.append(bar)

        fig = go.Figure(data=graph_data)

        fig.update_layout(
            title=dict(
                text='Compliance Findings by Service Category',
                font=dict(size=18, color='#111827', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', weight=600),
                x=0.5,
                xanchor='center'
            ),
            yaxis=dict(
                title='Failed Resources',
                titlefont=dict(size=14, color='#4B5563', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                tickfont=dict(size=12, color='#6B7280'),
                gridcolor='#E5E7EB',
                gridwidth=1,
                showgrid=True,
                zeroline=False
            ),
            xaxis=dict(
                tickangle=-45,
                tickfont=dict(size=11, color='#6B7280', family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
                showgrid=False
            ),
            barmode='group',
            plot_bgcolor='rgba(249, 250, 251, 0.5)',
            paper_bgcolor='white',
            margin=dict(l=60, r=40, t=100, b=120),
            font=dict(family='Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'),
            legend=dict(
                orientation='v',
                yanchor='top',
                y=1,
                xanchor='left',
                x=1.02,
                bgcolor='rgba(255, 255, 255, 0.9)',
                bordercolor='#E5E7EB',
                borderwidth=1,
                font=dict(size=11, color='#374151')
            ),
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