"""
Dashboard components for reusable UI elements.
"""

import dash
from dash import dcc, html, Input, Output, callback
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta


def create_metric_card(title: str, value: str, color: str = "#007bff"):
    """Create a metric card component."""
    return html.Div([
        html.H4(value, style={'color': color, 'fontSize': 32, 'margin': 0}),
        html.P(title, style={'margin': 0, 'fontSize': 14})
    ], style={
        'textAlign': 'center',
        'border': '1px solid #ddd',
        'padding': 20,
        'borderRadius': 5,
        'backgroundColor': '#fff'
    })


def create_alert_severity_badge(severity: str):
    """Create a colored badge for alert severity."""
    color_map = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#fd7e14',
        'CRITICAL': '#dc3545'
    }
    
    return html.Span(
        severity,
        style={
            'backgroundColor': color_map.get(severity, '#6c757d'),
            'color': 'white',
            'padding': '4px 8px',
            'borderRadius': '4px',
            'fontSize': '12px',
            'fontWeight': 'bold'
        }
    )


def create_status_badge(status: str):
    """Create a colored badge for status."""
    color_map = {
        'open': '#dc3545',
        'acknowledged': '#ffc107',
        'resolved': '#28a745',
        'investigating': '#17a2b8'
    }
    
    return html.Span(
        status.title(),
        style={
            'backgroundColor': color_map.get(status, '#6c757d'),
            'color': 'white',
            'padding': '4px 8px',
            'borderRadius': '4px',
            'fontSize': '12px',
            'fontWeight': 'bold'
        }
    )


def create_loading_spinner():
    """Create a loading spinner component."""
    return html.Div([
        html.Div(className='loading-spinner')
    ], style={
        'textAlign': 'center',
        'padding': '50px'
    })


def create_empty_state(message: str = "No data available"):
    """Create an empty state component."""
    return html.Div([
        html.H3(message, style={'color': '#6c757d', 'textAlign': 'center'}),
        html.P("Try adjusting your filters or check back later.", 
               style={'color': '#6c757d', 'textAlign': 'center'})
    ], style={
        'padding': '50px',
        'border': '2px dashed #dee2e6',
        'borderRadius': '5px',
        'backgroundColor': '#f8f9fa'
    })


def create_filter_section():
    """Create filter section for dashboard."""
    return html.Div([
        html.H4("Filters", style={'marginBottom': 20}),
        
        html.Div([
            html.Label("Date Range:"),
            dcc.DatePickerRange(
                id='filter-date-range',
                start_date=datetime.utcnow() - timedelta(days=7),
                end_date=datetime.utcnow(),
                display_format='YYYY-MM-DD'
            )
        ], style={'marginBottom': 15}),
        
        html.Div([
            html.Label("Application:"),
            dcc.Dropdown(
                id='filter-application',
                placeholder="Select application...",
                multi=True
            )
        ], style={'marginBottom': 15}),
        
        html.Div([
            html.Label("Severity:"),
            dcc.Dropdown(
                id='filter-severity',
                options=[
                    {'label': 'Low', 'value': 'LOW'},
                    {'label': 'Medium', 'value': 'MEDIUM'},
                    {'label': 'High', 'value': 'HIGH'},
                    {'label': 'Critical', 'value': 'CRITICAL'}
                ],
                placeholder="Select severity...",
                multi=True
            )
        ], style={'marginBottom': 15}),
        
        html.Button(
            "Apply Filters",
            id='apply-filters-btn',
            n_clicks=0,
            style={
                'backgroundColor': '#007bff',
                'color': 'white',
                'border': 'none',
                'padding': '10px 20px',
                'borderRadius': '4px',
                'cursor': 'pointer'
            }
        )
    ], style={
        'padding': '20px',
        'backgroundColor': '#f8f9fa',
        'borderRadius': '5px',
        'marginBottom': '20px'
    })


def create_alert_details_modal():
    """Create modal for alert details."""
    return html.Div([
        html.Div([
            html.Div([
                html.H3("Alert Details"),
                html.Div(id='alert-details-content'),
                html.Button(
                    "Close",
                    id='close-modal-btn',
                    style={
                        'marginTop': '20px',
                        'backgroundColor': '#6c757d',
                        'color': 'white',
                        'border': 'none',
                        'padding': '10px 20px',
                        'borderRadius': '4px',
                        'cursor': 'pointer'
                    }
                )
            ], style={
                'padding': '20px',
                'backgroundColor': 'white',
                'borderRadius': '5px',
                'maxWidth': '600px',
                'margin': 'auto'
            })
        ], style={
            'position': 'fixed',
            'top': '0',
            'left': '0',
            'width': '100%',
            'height': '100%',
            'backgroundColor': 'rgba(0,0,0,0.5)',
            'display': 'flex',
            'alignItems': 'center',
            'justifyContent': 'center',
            'zIndex': '1000'
        }),
        html.Div(id='modal-backdrop', style={'display': 'none'})
    ], id='alert-modal', style={'display': 'none'})


def create_user_activity_timeline():
    """Create user activity timeline component."""
    return html.Div([
        html.H4("User Activity Timeline"),
        dcc.Graph(id='user-timeline-chart'),
        html.Div([
            html.Label("Select User:"),
            dcc.Dropdown(
                id='user-selector',
                placeholder="Select user...",
                searchable=True
            )
        ], style={'marginTop': 20})
    ])


def create_risk_score_gauge(score: int, title: str = "Risk Score"):
    """Create a gauge chart for risk score."""
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': title},
        delta = {'reference': 50},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 25], 'color': "lightgray"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    return dcc.Graph(figure=fig, style={'height': '300px'})


def create_top_users_table(users_data):
    """Create table for top users by activity."""
    return html.Div([
        html.H4("Top Active Users"),
        html.Table([
            html.Thead([
                html.Tr([
                    html.Th("User"),
                    html.Th("Email"),
                    html.Th("Activity Count"),
                    html.Th("Risk Score")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(user['name']),
                    html.Td(user['email']),
                    html.Td(f"{user['activity_count']:,}"),
                    html.Td(create_alert_severity_badge(
                        'LOW' if user['risk_score'] < 30 else
                        'MEDIUM' if user['risk_score'] < 60 else
                        'HIGH' if user['risk_score'] < 80 else 'CRITICAL'
                    ))
                ]) for user in users_data
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'marginTop': '10px'
        })
    ])


def create_export_buttons():
    """Create export buttons for data."""
    return html.Div([
        html.Button(
            "Export to CSV",
            id='export-csv-btn',
            style={
                'backgroundColor': '#28a745',
                'color': 'white',
                'border': 'none',
                'padding': '8px 16px',
                'borderRadius': '4px',
                'marginRight': '10px',
                'cursor': 'pointer'
            }
        ),
        html.Button(
            "Export to PDF",
            id='export-pdf-btn',
            style={
                'backgroundColor': '#dc3545',
                'color': 'white',
                'border': 'none',
                'padding': '8px 16px',
                'borderRadius': '4px',
                'marginRight': '10px',
                'cursor': 'pointer'
            }
        ),
        html.Button(
            "Generate Report",
            id='generate-report-btn',
            style={
                'backgroundColor': '#007bff',
                'color': 'white',
                'border': 'none',
                'padding': '8px 16px',
                'borderRadius': '4px',
                'cursor': 'pointer'
            }
        )
    ], style={'marginBottom': '20px'})
