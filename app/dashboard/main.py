"""
Main dashboard application using Dash.
"""

import dash
from dash import dcc, html, Input, Output, callback, dash_table
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd
import structlog

from app.core.database import SessionLocal
from app.core.models import Alert, AccessLog, PolicyViolation, SaaSApplication, AlertSeverity
from app.services.monitoring import MonitoringService
from app.services.alerts import AlertService

logger = structlog.get_logger()

# Initialize Dash app
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])
app.title = "CASB Security Dashboard"

# Layout
app.layout = html.Div([
    html.H1("Cloud Access Security Broker Dashboard", 
            style={'textAlign': 'center', 'marginBottom': 30}),
    
    # Date range selector
    html.Div([
        html.Label("Select Date Range:"),
        dcc.DatePickerRange(
            id='date-picker-range',
            start_date=datetime.utcnow() - timedelta(days=7),
            end_date=datetime.utcnow(),
            display_format='YYYY-MM-DD'
        )
    ], style={'marginBottom': 20}),
    
    # Key Metrics Cards
    html.Div(id='metrics-cards', style={'marginBottom': 30}),
    
    # Charts Row 1
    html.Div([
        html.Div([
            html.H3("Alert Trends", style={'textAlign': 'center'}),
            dcc.Graph(id='alert-trends-chart')
        ], className='six columns'),
        
        html.Div([
            html.H3("Access Log Volume", style={'textAlign': 'center'}),
            dcc.Graph(id='access-volume-chart')
        ], className='six columns')
    ], className='row'),
    
    # Charts Row 2
    html.Div([
        html.Div([
            html.H3("Alert Severity Distribution", style={'textAlign': 'center'}),
            dcc.Graph(id='severity-distribution-chart')
        ], className='six columns'),
        
        html.Div([
            html.H3("Top Applications", style={'textAlign': 'center'}),
            dcc.Graph(id='top-apps-chart')
        ], className='six columns')
    ], className='row'),
    
    # Recent Alerts Table
    html.Div([
        html.H3("Recent Security Alerts"),
        html.Div(id='recent-alerts-table')
    ], style={'marginTop': 30}),
    
    # Policy Violations
    html.Div([
        html.H3("Recent Policy Violations"),
        html.Div(id='policy-violations-table')
    ], style={'marginTop': 30}),
    
    # Auto-refresh interval
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # 30 seconds
        n_intervals=0
    )
])


def get_db_session():
    """Get database session."""
    return SessionLocal()


@callback(
    [Output('metrics-cards', 'children'),
     Output('alert-trends-chart', 'figure'),
     Output('access-volume-chart', 'figure'),
     Output('severity-distribution-chart', 'figure'),
     Output('top-apps-chart', 'figure'),
     Output('recent-alerts-table', 'children'),
     Output('policy-violations-table', 'children')],
    [Input('date-picker-range', 'start_date'),
     Input('date-picker-range', 'end_date'),
     Input('interval-component', 'n_intervals')]
)
def update_dashboard(start_date, end_date, n_intervals):
    """Update dashboard with latest data."""
    db = get_db_session()
    try:
        # Convert dates
        start_dt = datetime.fromisoformat(start_date) if start_date else datetime.utcnow() - timedelta(days=7)
        end_dt = datetime.fromisoformat(end_date) if end_date else datetime.utcnow()
        
        # Get metrics
        metrics_cards = create_metrics_cards(db, start_dt, end_dt)
        
        # Get charts
        alert_trends_fig = create_alert_trends_chart(db, start_dt, end_dt)
        access_volume_fig = create_access_volume_chart(db, start_dt, end_dt)
        severity_dist_fig = create_severity_distribution_chart(db, start_dt, end_dt)
        top_apps_fig = create_top_apps_chart(db, start_dt, end_dt)
        
        # Get tables
        alerts_table = create_recent_alerts_table(db, start_dt, end_dt)
        violations_table = create_policy_violations_table(db, start_dt, end_dt)
        
        return (
            metrics_cards,
            alert_trends_fig,
            access_volume_fig,
            severity_dist_fig,
            top_apps_fig,
            alerts_table,
            violations_table
        )
    finally:
        db.close()


def create_metrics_cards(db, start_dt, end_dt):
    """Create metrics cards."""
    # Get counts
    total_alerts = db.query(Alert).filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt
    ).count()
    
    critical_alerts = db.query(Alert).filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt,
        Alert.severity == AlertSeverity.CRITICAL
    ).count()
    
    total_violations = db.query(PolicyViolation).filter(
        PolicyViolation.timestamp >= start_dt,
        PolicyViolation.timestamp <= end_dt
    ).count()
    
    total_access_logs = db.query(AccessLog).filter(
        AccessLog.timestamp >= start_dt,
        AccessLog.timestamp <= end_dt
    ).count()
    
    # Active applications
    active_apps = db.query(SaaSApplication).filter(
        SaaSApplication.is_active == True
    ).count()
    
    return html.Div([
        html.Div([
            html.H4(f"{total_alerts}", style={'color': '#007bff', 'fontSize': 32}),
            html.P("Total Alerts")
        ], className='three columns', style={'textAlign': 'center', 'border': '1px solid #ddd', 'padding': 20}),
        
        html.Div([
            html.H4(f"{critical_alerts}", style={'color': '#dc3545', 'fontSize': 32}),
            html.P("Critical Alerts")
        ], className='three columns', style={'textAlign': 'center', 'border': '1px solid #ddd', 'padding': 20}),
        
        html.Div([
            html.H4(f"{total_violations}", style={'color': '#ffc107', 'fontSize': 32}),
            html.P("Policy Violations")
        ], className='three columns', style={'textAlign': 'center', 'border': '1px solid #ddd', 'padding': 20}),
        
        html.Div([
            html.H4(f"{total_access_logs:,}", style={'color': '#28a745', 'fontSize': 32}),
            html.P("Access Logs")
        ], className='three columns', style={'textAlign': 'center', 'border': '1px solid #ddd', 'padding': 20})
    ], className='row')


def create_alert_trends_chart(db, start_dt, end_dt):
    """Create alert trends chart."""
    # Get daily alert counts
    daily_alerts = db.query(
        func.date(Alert.created_at).label('date'),
        func.count(Alert.id).label('count')
    ).filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt
    ).group_by(func.date(Alert.created_at)).all()
    
    if not daily_alerts:
        return go.Figure().add_annotation(text="No data available", xref="paper", yref="paper")
    
    df = pd.DataFrame(daily_alerts, columns=['date', 'count'])
    
    fig = px.line(df, x='date', y='count', title='Daily Alert Trends')
    fig.update_layout(xaxis_title='Date', yaxis_title='Number of Alerts')
    
    return fig


def create_access_volume_chart(db, start_dt, end_dt):
    """Create access volume chart."""
    # Get hourly access log counts
    hourly_access = db.query(
        func.extract('hour', AccessLog.timestamp).label('hour'),
        func.count(AccessLog.id).label('count')
    ).filter(
        AccessLog.timestamp >= start_dt,
        AccessLog.timestamp <= end_dt
    ).group_by(func.extract('hour', AccessLog.timestamp)).all()
    
    if not hourly_access:
        return go.Figure().add_annotation(text="No data available", xref="paper", yref="paper")
    
    df = pd.DataFrame(hourly_access, columns=['hour', 'count'])
    df = df.sort_values('hour')
    
    fig = px.bar(df, x='hour', y='count', title='Access Volume by Hour')
    fig.update_layout(xaxis_title='Hour of Day', yaxis_title='Number of Access Events')
    
    return fig


def create_severity_distribution_chart(db, start_dt, end_dt):
    """Create severity distribution chart."""
    # Get alert counts by severity
    severity_counts = db.query(
        Alert.severity,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt
    ).group_by(Alert.severity).all()
    
    if not severity_counts:
        return go.Figure().add_annotation(text="No data available", xref="paper", yref="paper")
    
    df = pd.DataFrame(severity_counts, columns=['severity', 'count'])
    df['severity'] = df['severity'].apply(lambda x: x.value)
    
    fig = px.pie(df, values='count', names='severity', title='Alert Severity Distribution')
    
    return fig


def create_top_apps_chart(db, start_dt, end_dt):
    """Create top applications chart."""
    # Get access counts by application
    app_counts = db.query(
        SaaSApplication.name,
        func.count(AccessLog.id).label('count')
    ).join(AccessLog).filter(
        AccessLog.timestamp >= start_dt,
        AccessLog.timestamp <= end_dt
    ).group_by(SaaSApplication.name).order_by(func.count(AccessLog.id).desc()).limit(10).all()
    
    if not app_counts:
        return go.Figure().add_annotation(text="No data available", xref="paper", yref="paper")
    
    df = pd.DataFrame(app_counts, columns=['application', 'count'])
    
    fig = px.bar(df, x='count', y='application', orientation='h', title='Top Applications by Access Volume')
    fig.update_layout(xaxis_title='Access Count', yaxis_title='Application')
    
    return fig


def create_recent_alerts_table(db, start_dt, end_dt):
    """Create recent alerts table."""
    recent_alerts = db.query(Alert).filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt
    ).order_by(Alert.created_at.desc()).limit(10).all()
    
    if not recent_alerts:
        return html.P("No recent alerts")
    
    data = []
    for alert in recent_alerts:
        data.append({
            'ID': alert.id,
            'Title': alert.title,
            'Severity': alert.severity.value,
            'Status': alert.status,
            'Created': alert.created_at.strftime('%Y-%m-%d %H:%M'),
            'User': alert.details.get('user_email', 'N/A') if alert.details else 'N/A'
        })
    
    return dash_table.DataTable(
        data=data,
        columns=[{'name': col, 'id': col} for col in data[0].keys()] if data else [],
        style_table={'overflowX': 'auto'},
        style_cell={'textAlign': 'left', 'padding': '10px'},
        style_header={'backgroundColor': '#f8f9fa', 'fontWeight': 'bold'},
        style_data_conditional=[
            {
                'if': {'filter_query': '{Severity} = CRITICAL'},
                'backgroundColor': '#f8d7da',
                'color': 'black',
            },
            {
                'if': {'filter_query': '{Severity} = HIGH'},
                'backgroundColor': '#fff3cd',
                'color': 'black',
            }
        ]
    )


def create_policy_violations_table(db, start_dt, end_dt):
    """Create policy violations table."""
    violations = db.query(PolicyViolation).filter(
        PolicyViolation.timestamp >= start_dt,
        PolicyViolation.timestamp <= end_dt
    ).order_by(PolicyViolation.timestamp.desc()).limit(10).all()
    
    if not violations:
        return html.P("No recent policy violations")
    
    data = []
    for violation in violations:
        data.append({
            'ID': violation.id,
            'User': violation.user_email,
            'Action': violation.action,
            'Severity': violation.severity.value,
            'Status': violation.status,
            'Time': violation.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    
    return dash_table.DataTable(
        data=data,
        columns=[{'name': col, 'id': col} for col in data[0].keys()] if data else [],
        style_table={'overflowX': 'auto'},
        style_cell={'textAlign': 'left', 'padding': '10px'},
        style_header={'backgroundColor': '#f8f9fa', 'fontWeight': 'bold'}
    )


if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
