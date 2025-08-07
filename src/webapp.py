from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import logging
from datetime import datetime, timedelta
import os
import folium
import plotly.graph_objs as go
import plotly.utils
from werkzeug.utils import secure_filename

from config import config
from database import DatabaseManager
from forensics import ForensicAnalyzer
from osint import OSINTCollector
from correlation import CorrelationEngine
from ollama_manager import OllamaModelManager

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = config.FLASK_SECRET_KEY

db_manager = DatabaseManager(config.DATABASE_PATH)
forensic_analyzer = ForensicAnalyzer()
osint_collector = OSINTCollector(config)
correlation_engine = CorrelationEngine(config)
ollama_manager = OllamaModelManager(config)

@app.route('/')
def index():
    investigations = db_manager.get_investigations()
    return render_template('index.html', investigations=investigations)

@app.route('/create_investigation', methods=['GET', 'POST'])
def create_investigation():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        location = request.form.get('location', '')
        timezone = request.form.get('timezone', 'UTC')
        
        investigation_id = db_manager.create_investigation(
            name=name,
            description=description,
            location=location,
            timezone=timezone
        )
        
        return redirect(url_for('investigation_detail', investigation_id=investigation_id))
    
    return render_template('create_investigation.html')

@app.route('/investigation/<int:investigation_id>')
def investigation_detail(investigation_id):
    investigation = db_manager.get_investigation(investigation_id)
    if not investigation:
        return "Investigation not found", 404
    
    stats = db_manager.get_investigation_statistics(investigation_id)
    correlations = db_manager.get_correlations(investigation_id, min_strength=0.5, limit=10)
    
    return render_template('investigation_detail.html', 
                         investigation=investigation, 
                         stats=stats,
                         correlations=correlations)

@app.route('/investigation/<int:investigation_id>/upload_evidence', methods=['POST'])
def upload_evidence(investigation_id):
    try:
        files = request.files.getlist('evidence_files')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files selected'}), 400
        
        timezone = request.form.get('timezone', 'UTC')
        total_events = 0
        processed_files = []
        errors = []
        
        for file in files:
            if file.filename == '':
                continue
                
            try:
                filename = secure_filename(file.filename)
                upload_path = os.path.join('evidence', filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                
                logger.info(f"Processing evidence file: {upload_path}")
                forensic_events = forensic_analyzer.parse_evidence_file(upload_path, timezone)
                
                if forensic_events:
                    db_manager.save_forensic_events(investigation_id, forensic_events)
                    total_events += len(forensic_events)
                    processed_files.append(f"{filename}: {len(forensic_events)} events")
                    logger.info(f"Saved {len(forensic_events)} forensic events from {filename}")
                else:
                    errors.append(f"{filename}: No forensic events found")
                    
            except ImportError as e:
                logger.error(f"Missing dependency for {filename}: {e}")
                errors.append(f"{filename}: Missing dependency - {str(e)}")
            except ValueError as e:
                logger.error(f"Invalid file {filename}: {e}")
                errors.append(f"{filename}: Invalid file - {str(e)}")
            except FileNotFoundError as e:
                logger.error(f"File not found {filename}: {e}")
                errors.append(f"{filename}: File not found - {str(e)}")
            except Exception as e:
                logger.error(f"Error processing {filename}: {e}")
                errors.append(f"{filename}: {str(e)}")
        
        if total_events > 0:
            message = f'Successfully processed {total_events} forensic events from {len(processed_files)} file(s)'
            if errors:
                message += f'. {len(errors)} file(s) had errors.'
            
            response_data = {
                'success': True,
                'message': message,
                'event_count': total_events,
                'processed_files': processed_files
            }
            
            if errors:
                response_data['warnings'] = errors
                
            return jsonify(response_data)
        else:
            error_msg = 'No forensic events found in any uploaded files'
            if errors:
                error_msg += f'. Errors: {"; ".join(errors)}'
            return jsonify({'error': error_msg}), 400
            
    except Exception as e:
        logger.error(f"Error processing evidence: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/collect_osint', methods=['POST'])
def collect_osint(investigation_id):
    try:
        data = request.json
        location = data.get('location')
        start_time = datetime.fromisoformat(data.get('start_time'))
        end_time = datetime.fromisoformat(data.get('end_time'))
        keywords = data.get('keywords', [])
        subreddits = data.get('subreddits', [])
        
        logger.info(f"Collecting OSINT data for investigation {investigation_id}")
        
        # grab forensic data to help the LLM search smarter
        forensic_events = db_manager.get_forensic_events(investigation_id)
        
        osint_data = osint_collector.collect_all_sources(
            location=location,
            start_time=start_time,
            end_time=end_time,
            keywords=keywords,
            subreddits=subreddits,
            forensic_context=forensic_events
        )
        
        if osint_data:
            db_manager.save_osint_data(investigation_id, osint_data)
            
            return jsonify({
                'success': True,
                'message': f'Successfully collected {len(osint_data)} OSINT items',
                'item_count': len(osint_data)
            })
        else:
            return jsonify({'warning': 'No OSINT data collected'}), 200
            
    except Exception as e:
        logger.error(f"Error collecting OSINT data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/run_correlation', methods=['POST'])
def run_correlation(investigation_id):
    try:
        investigation = db_manager.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        forensic_events = db_manager.get_forensic_events(investigation_id)
        osint_data = db_manager.get_osint_data(investigation_id)
        
        if not forensic_events or not osint_data:
            return jsonify({'error': 'Need both forensic events and OSINT data to run correlation'}), 400
        
        location_data = None
        if investigation['location']:
            try:
                from geopy.geocoders import Nominatim
                geolocator = Nominatim(user_agent=config.REDDIT_USER_AGENT)
                location_obj = geolocator.geocode(investigation['location'])
                if location_obj:
                    location_data = {
                        'lat': location_obj.latitude,
                        'lon': location_obj.longitude
                    }
            except Exception as e:
                logger.warning(f"Could not geocode location: {e}")
        
        correlations = correlation_engine.correlate_forensic_osint(
            forensic_events, osint_data, location_data
        )
        
        if correlations:
            db_manager.save_correlations(investigation_id, correlations)
            
            correlation_report = correlation_engine.generate_correlation_report(correlations)
            
            # throw in some LLM analysis if we can
            llm_insights = None
            if config.OLLAMA_ENABLE:
                try:
                    llm_insights = correlation_engine.analyze_correlation_patterns_with_llm(correlations)
                    llm_summary = correlation_engine.generate_llm_investigation_summary(
                        correlations, forensic_events, osint_data
                    )
                    correlation_report['llm_insights'] = llm_insights
                    correlation_report['llm_summary'] = llm_summary
                except Exception as e:
                    logger.warning(f"LLM analysis failed: {e}")
            
            return jsonify({
                'success': True,
                'message': f'Found {len(correlations)} correlations',
                'report': correlation_report
            })
        else:
            return jsonify({'warning': 'No correlations found'}), 200
            
    except Exception as e:
        logger.error(f"Error running correlation: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/timeline')
def timeline_view(investigation_id):
    investigation = db_manager.get_investigation(investigation_id)
    if not investigation:
        return "Investigation not found", 404
    
    forensic_events = db_manager.get_forensic_events(investigation_id, limit=1000)
    osint_data = db_manager.get_osint_data(investigation_id, limit=1000)
    correlations = db_manager.get_correlations(investigation_id, min_strength=0.3)
    
    timeline_data = []
    
    for event in forensic_events:
        timeline_data.append({
            'timestamp': event['timestamp'],
            'type': 'forensic',
            'title': f"{event['event_type']} - {os.path.basename(event['file_path'])}",
            'description': event['file_path'],
            'data': event
        })
    
    for item in osint_data:
        timeline_data.append({
            'timestamp': item['timestamp'],
            'type': 'osint',
            'title': f"{item['source']} - {item.get('author', 'Unknown')}",
            'description': item['content'][:100] + '...',
            'data': item
        })
    
    timeline_data.sort(key=lambda x: x['timestamp'])
    
    return render_template('timeline.html', 
                         investigation=investigation,
                         timeline_data=timeline_data,
                         correlations=correlations)

@app.route('/investigation/<int:investigation_id>/map')
def map_view(investigation_id):
    investigation = db_manager.get_investigation(investigation_id)
    if not investigation:
        return "Investigation not found", 404
    
    osint_data = db_manager.get_osint_data(investigation_id)
    
    center_lat, center_lon = 39.8283, -98.5795
    if investigation['location']:
        try:
            from geopy.geocoders import Nominatim
            geolocator = Nominatim(user_agent=config.REDDIT_USER_AGENT)
            location_obj = geolocator.geocode(investigation['location'])
            if location_obj:
                center_lat, center_lon = location_obj.latitude, location_obj.longitude
        except Exception as e:
            logger.warning(f"Could not geocode location: {e}")
    
    map_obj = folium.Map(location=[center_lat, center_lon], zoom_start=10)
    
    for item in osint_data:
        if item.get('coordinates'):
            coords = item['coordinates']
            popup_content = f"""
            <b>{item['source']}</b><br>
            <b>Author:</b> {item.get('author', 'Unknown')}<br>
            <b>Time:</b> {item['timestamp']}<br>
            <b>Content:</b> {item['content'][:200]}...<br>
            <a href="{item.get('url', '#')}" target="_blank">View Original</a>
            """
            
            color = {
                'twitter': 'blue',
                'reddit': 'orange', 
                'news_api': 'green',
                'google_news': 'red'
            }.get(item['source'], 'gray')
            
            folium.Marker(
                [coords['lat'], coords['lon']],
                popup=folium.Popup(popup_content, max_width=300),
                icon=folium.Icon(color=color)
            ).add_to(map_obj)
    
    map_html = map_obj._repr_html_()
    
    return render_template('map.html',
                         investigation=investigation,
                         map_html=map_html)

@app.route('/investigation/<int:investigation_id>/analytics')
def analytics_view(investigation_id):
    investigation = db_manager.get_investigation(investigation_id)
    if not investigation:
        return "Investigation not found", 404
    
    forensic_events = db_manager.get_forensic_events(investigation_id)
    osint_data = db_manager.get_osint_data(investigation_id)
    correlations = db_manager.get_correlations(investigation_id)
    
    forensic_timeline = _create_forensic_timeline_chart(forensic_events)
    osint_sources_chart = _create_osint_sources_chart(osint_data)
    correlation_strength_chart = _create_correlation_strength_chart(correlations)
    
    return render_template('analytics.html',
                         investigation=investigation,
                         forensic_timeline=forensic_timeline,
                         osint_sources_chart=osint_sources_chart,
                         correlation_strength_chart=correlation_strength_chart)

def _create_forensic_timeline_chart(events):
    if not events:
        return json.dumps({})
    
    event_counts = {}
    for event in events:
        date = event['timestamp'].split('T')[0] if isinstance(event['timestamp'], str) else event['timestamp'].date()
        event_counts[str(date)] = event_counts.get(str(date), 0) + 1
    
    dates = sorted(event_counts.keys())
    counts = [event_counts[date] for date in dates]
    
    fig = go.Figure(data=go.Scatter(x=dates, y=counts, mode='lines+markers'))
    fig.update_layout(title='Forensic Events Timeline', xaxis_title='Date', yaxis_title='Event Count')
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def _create_osint_sources_chart(osint_data):
    if not osint_data:
        return json.dumps({})
    
    source_counts = {}
    for item in osint_data:
        source = item['source']
        source_counts[source] = source_counts.get(source, 0) + 1
    
    fig = go.Figure(data=go.Pie(labels=list(source_counts.keys()), values=list(source_counts.values())))
    fig.update_layout(title='OSINT Data Sources')
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def _create_correlation_strength_chart(correlations):
    if not correlations:
        return json.dumps({})
    
    strengths = [corr['correlation_strength'] for corr in correlations]
    
    fig = go.Figure(data=go.Histogram(x=strengths, nbinsx=20))
    fig.update_layout(title='Correlation Strength Distribution', xaxis_title='Strength', yaxis_title='Count')
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@app.route('/api/investigation/<int:investigation_id>/export')
def export_investigation(investigation_id):
    try:
        investigation = db_manager.get_investigation(investigation_id)
        forensic_events = db_manager.get_forensic_events(investigation_id)
        osint_data = db_manager.get_osint_data(investigation_id)
        correlations = db_manager.get_correlations(investigation_id)
        
        export_data = {
            'investigation': investigation,
            'forensic_events': forensic_events,
            'osint_data': osint_data,
            'correlations': correlations,
            'export_timestamp': datetime.now().isoformat()
        }
        
        return jsonify(export_data)
        
    except Exception as e:
        logger.error(f"Error exporting investigation: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/llm_analysis', methods=['POST'])
def run_llm_analysis(investigation_id):
    # let the LLM analyze everything we've got
    try:
        if not config.OLLAMA_ENABLE:
            return jsonify({'error': 'LLM analysis is disabled'}), 400
        
        investigation = db_manager.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        forensic_events = db_manager.get_forensic_events(investigation_id)
        osint_data = db_manager.get_osint_data(investigation_id)
        correlations = db_manager.get_correlations(investigation_id)
        
        if not forensic_events and not osint_data:
            return jsonify({'error': 'No data available for analysis'}), 400
        
        # have the LLM write up a full analysis
        llm_summary = correlation_engine.generate_llm_investigation_summary(
            correlations, forensic_events, osint_data
        )
        
        llm_insights = None
        if correlations:
            llm_insights = correlation_engine.analyze_correlation_patterns_with_llm(correlations)
        
        # see if there are any web trends to analyze
        web_trends = None
        if any(item.get('source') == 'web_intelligence' for item in osint_data):
            try:
                web_intel_items = [item for item in osint_data if item.get('source') == 'web_intelligence']
                if osint_collector.web_intelligence:
                    search_queries = [item.get('data', {}).get('search_query', '') for item in web_intel_items]
                    web_trends = osint_collector.web_intelligence.analyze_web_trend(
                        search_queries, investigation['location']
                    )
            except Exception as e:
                logger.warning(f"Web trend analysis failed: {e}")
        
        analysis_results = {
            'investigation_summary': llm_summary,
            'correlation_insights': llm_insights,
            'web_trends': web_trends,
            'analysis_timestamp': datetime.now().isoformat(),
            'llm_model': config.OLLAMA_MODEL
        }
        
        return jsonify({
            'success': True,
            'message': 'LLM analysis completed',
            'analysis': analysis_results
        })
        
    except Exception as e:
        logger.error(f"Error running LLM analysis: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/full_investigation', methods=['POST'])
def run_full_investigation(investigation_id):
    """Run complete investigation analysis on all uploaded evidence"""
    try:
        investigation = db_manager.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        forensic_events = db_manager.get_forensic_events(investigation_id)
        if not forensic_events:
            return jsonify({'error': 'No evidence uploaded. Please upload evidence files first.'}), 400
        
        data = request.json or {}
        context_notes = data.get('context_notes', '')
        
        logger.info(f"Running full investigation for investigation {investigation_id}")
        
        # first, let's gather some web intelligence
        if config.WEB_SEARCH_ENABLE and config.OLLAMA_ENABLE:
            try:
                # have the LLM create smart searches from our evidence
                web_intel_data = osint_collector.collect_web_intelligence(
                    forensic_context=forensic_events,
                    location=investigation.get('location', ''),
                    start_time=datetime.now() - timedelta(days=30),  # last 30 days seems reasonable
                    end_time=datetime.now(),
                    context_notes=context_notes
                )
                
                if web_intel_data:
                    db_manager.save_osint_data(investigation_id, web_intel_data)
                    logger.info(f"Collected {len(web_intel_data)} web intelligence items")
            except Exception as e:
                logger.warning(f"Web intelligence collection failed: {e}")
        
        # now let's see what correlates
        osint_data = db_manager.get_osint_data(investigation_id)
        location_data = None
        
        if investigation.get('location'):
            try:
                from geopy.geocoders import Nominatim
                geolocator = Nominatim(user_agent=config.REDDIT_USER_AGENT)
                location_obj = geolocator.geocode(investigation['location'])
                if location_obj:
                    location_data = {
                        'lat': location_obj.latitude,
                        'lon': location_obj.longitude
                    }
            except Exception as e:
                logger.warning(f"Could not geocode location: {e}")
        
        correlations = []
        if osint_data:
            correlations = correlation_engine.correlate_forensic_osint(
                forensic_events, osint_data, location_data
            )
            
            if correlations:
                db_manager.save_correlations(investigation_id, correlations)
                logger.info(f"Found {len(correlations)} correlations")
        
        # time for the LLM to work its magic
        analysis_results = {}
        if config.OLLAMA_ENABLE:
            try:
                # have the LLM write up what it found
                llm_summary = correlation_engine.generate_llm_investigation_summary(
                    correlations, forensic_events, osint_data, context_notes
                )
                
                # look for patterns in the correlations
                llm_insights = None
                if correlations:
                    llm_insights = correlation_engine.analyze_correlation_patterns_with_llm(correlations)
                
                analysis_results = {
                    'investigation_summary': llm_summary,
                    'correlation_insights': llm_insights,
                    'context_notes': context_notes,
                    'analysis_timestamp': datetime.now().isoformat(),
                    'llm_model': config.OLLAMA_MODEL
                }
            except Exception as e:
                logger.warning(f"LLM analysis failed: {e}")
        
        # package up the results
        response_data = {
            'success': True,
            'message': f'Full investigation completed successfully',
            'results': {
                'forensic_events_count': len(forensic_events),
                'osint_items_count': len(osint_data) if osint_data else 0,
                'correlations_count': len(correlations),
                'analysis': analysis_results
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error running full investigation: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/investigation/<int:investigation_id>/web_intelligence', methods=['POST'])
def collect_web_intelligence(investigation_id):
    """Collect web intelligence using LLM-powered search with context notes"""
    try:
        if not config.WEB_SEARCH_ENABLE:
            return jsonify({'error': 'Web intelligence collection is disabled'}), 400
        
        data = request.json
        location = data.get('location', '')
        start_time_str = data.get('start_time')
        end_time_str = data.get('end_time')
        context_notes = data.get('context_notes', '')
        
        # set some defaults if user didn't specify
        start_time = datetime.fromisoformat(start_time_str) if start_time_str else datetime.now() - timedelta(days=30)
        end_time = datetime.fromisoformat(end_time_str) if end_time_str else datetime.now()
        
        # grab the forensic stuff to make searches smarter
        forensic_events = db_manager.get_forensic_events(investigation_id)
        
        logger.info(f"Collecting web intelligence for investigation {investigation_id}")
        
        web_intel_data = osint_collector.collect_web_intelligence(
            forensic_context=forensic_events,
            location=location,
            start_time=start_time,
            end_time=end_time,
            context_notes=context_notes
        )
        
        if web_intel_data:
            db_manager.save_osint_data(investigation_id, web_intel_data)
            
            return jsonify({
                'success': True,
                'message': f'Collected {len(web_intel_data)} web intelligence items',
                'item_count': len(web_intel_data)
            })
        else:
            return jsonify({'warning': 'No web intelligence data collected'}), 200
            
    except Exception as e:
        logger.error(f"Error collecting web intelligence: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/llm_status')
def llm_status():
    # see if the LLM is working
    try:
        from llm_client import OllamaClient
        
        llm_client = OllamaClient(config)
        status = {
            'ollama_enabled': config.OLLAMA_ENABLE,
            'ollama_host': config.OLLAMA_HOST,
            'ollama_model': config.OLLAMA_MODEL,
            'web_search_enabled': config.WEB_SEARCH_ENABLE,
            'web_search_engine': config.WEB_SEARCH_ENGINE,
            'llm_available': llm_client.is_available() if llm_client else False
        }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error checking LLM status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/models')
def models_page():
    # page for managing ollama models
    model_status = ollama_manager.get_model_status()
    return render_template('models.html', **model_status)

@app.route('/api/models/status')
def api_models_status():
    # API endpoint for model status
    try:
        model_status = ollama_manager.get_model_status()
        return jsonify(model_status)
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/pull', methods=['POST'])
def api_models_pull():
    # download a new model
    try:
        data = request.json
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({'error': 'Model name is required'}), 400
        
        result = ollama_manager.pull_model(model_name)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error pulling model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/delete', methods=['POST'])
def api_models_delete():
    # remove a model
    try:
        data = request.json
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({'error': 'Model name is required'}), 400
        
        result = ollama_manager.delete_model(model_name)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error deleting model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/test', methods=['POST'])
def api_models_test():
    # check if a model works
    try:
        data = request.json
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({'error': 'Model name is required'}), 400
        
        result = ollama_manager.test_model(model_name)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error testing model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/set_active', methods=['POST'])
def api_models_set_active():
    # switch to a different model
    try:
        data = request.json
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({'error': 'Model name is required'}), 400
        
        result = ollama_manager.set_active_model(model_name)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error setting active model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigation/<int:investigation_id>/delete', methods=['POST'])
def delete_investigation(investigation_id):
    # nuke an investigation completely
    try:
        investigation = db_manager.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        success = db_manager.delete_investigation(investigation_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Investigation "{investigation["name"]}" deleted successfully'
            })
        else:
            return jsonify({'error': 'Investigation not found or already deleted'}), 404
            
    except Exception as e:
        logger.error(f"Error deleting investigation: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG
    )