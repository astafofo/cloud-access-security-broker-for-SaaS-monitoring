"""
Dashboard callbacks for interactivity.
"""

from dash import Input, Output, State, callback
import dash_table
import pandas as pd
from datetime import datetime, timedelta
import structlog

from app.core.database import SessionLocal
from app.core.models import Alert, AccessLog, PolicyViolation, SaaSApplication, User

logger = structlog.get_logger()


def register_callbacks(app):
    """Register all dashboard callbacks."""
    
    @callback(
        Output('alert-details-content', 'children'),
        Output('alert-modal', 'style'),
        Input('recent-alerts-table', 'active_cell'),
        State('recent-alerts-table', 'data')
    )
    def show_alert_details(active_cell, table_data):
        """Show alert details when a row is clicked."""
        if not active_cell or not table_data:
            return [], {'display': 'none'}
        
        row_index = active_cell['row']
        alert_id = table_data[row_index]['ID']
        
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return [], {'display': 'none'}
            
            details = [
                html.Div([
                    html.H5("Alert Information"),
                    html.P(f"Title: {alert.title}"),
                    html.P(f"Description: {alert.description}"),
                    html.P(f"Severity: {alert.severity.value}"),
                    html.P(f"Status: {alert.status}"),
                    html.P(f"Created: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}"),
                ]),
                
                html.Div([
                    html.H5("Additional Details"),
                    html.Pre(str(alert.details)) if alert.details else html.P("No additional details")
                ], style={'marginTop': '20px'})
            ]
            
            return details, {'display': 'block'}
            
        finally:
            db.close()
    
    @callback(
        Output('alert-modal', 'style', allow_duplicate=True),
        Input('close-modal-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def close_modal(n_clicks):
        """Close the modal."""
        if n_clicks:
            return {'display': 'none'}
        return {'display': 'none'}
    
    @callback(
        Output('filter-application', 'options'),
        Input('interval-component', 'n_intervals')
    )
    def update_application_options(n_intervals):
        """Update application filter options."""
        db = SessionLocal()
        try:
            applications = db.query(SaaSApplication).filter(
                SaaSApplication.is_active == True
            ).all()
            
            options = [
                {'label': app.name, 'value': app.id}
                for app in applications
            ]
            
            return options
            
        finally:
            db.close()
    
    @callback(
        Output('user-selector', 'options'),
        Input('interval-component', 'n_intervals')
    )
    def update_user_options(n_intervals):
        """Update user selector options."""
        db = SessionLocal()
        try:
            # Get active users from recent logs
            recent_cutoff = datetime.utcnow() - timedelta(days=7)
            users = db.query(AccessLog.user_email).filter(
                AccessLog.timestamp >= recent_cutoff
            ).distinct().limit(100).all()
            
            options = [
                {'label': user[0], 'value': user[0]}
                for user in users
            ]
            
            return options
            
        finally:
            db.close()
    
    @callback(
        Output('user-timeline-chart', 'figure'),
        Input('user-selector', 'value'),
        State('date-picker-range', 'start_date'),
        State('date-picker-range', 'end_date')
    )
    def update_user_timeline(selected_user, start_date, end_date):
        """Update user activity timeline."""
        if not selected_user:
            return {}
        
        db = SessionLocal()
        try:
            start_dt = datetime.fromisoformat(start_date) if start_date else datetime.utcnow() - timedelta(days=7)
            end_dt = datetime.fromisoformat(end_date) if end_date else datetime.utcnow()
            
            # Get user activity
            activities = db.query(AccessLog).filter(
                AccessLog.user_email == selected_user,
                AccessLog.timestamp >= start_dt,
                AccessLog.timestamp <= end_dt
            ).order_by(AccessLog.timestamp).all()
            
            if not activities:
                return {}
            
            # Prepare data for timeline
            data = []
            for activity in activities:
                data.append({
                    'timestamp': activity.timestamp,
                    'action': activity.action,
                    'resource': activity.resource,
                    'ip_address': activity.ip_address
                })
            
            df = pd.DataFrame(data)
            
            # Create timeline chart
            fig = {
                'data': [
                    {
                        'x': df['timestamp'],
                        'y': df['action'],
                        'type': 'scatter',
                        'mode': 'markers+lines',
                        'name': 'Activities',
                        'text': df['resource'],
                        'hovertemplate': '<b>%{y}</b><br>%{x}<br>Resource: %{text}<extra></extra>'
                    }
                ],
                'layout': {
                    'title': f'Activity Timeline for {selected_user}',
                    'xaxis': {'title': 'Time'},
                    'yaxis': {'title': 'Action'},
                    'height': 400
                }
            }
            
            return fig
            
        finally:
            db.close()
    
    @callback(
        Output('export-csv-btn', 'n_clicks'),
        Input('export-csv-btn', 'n_clicks'),
        State('date-picker-range', 'start_date'),
        State('date-picker-range', 'end_date'),
        prevent_initial_call=True
    )
    def export_to_csv(n_clicks, start_date, end_date):
        """Export data to CSV."""
        if n_clicks:
            # This would trigger a download
            # Implementation would depend on the specific data being exported
            logger.info("CSV export requested")
        
        return n_clicks
    
    @callback(
        Output('generate-report-btn', 'n_clicks'),
        Input('generate-report-btn', 'n_clicks'),
        State('date-picker-range', 'start_date'),
        State('date-picker-range', 'end_date'),
        prevent_initial_call=True
    )
    def generate_report(n_clicks, start_date, end_date):
        """Generate comprehensive report."""
        if n_clicks:
            # This would generate and serve a PDF report
            logger.info("Report generation requested")
        
        return n_clicks
