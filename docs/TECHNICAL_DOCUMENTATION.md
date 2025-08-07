# Sift - Technical Documentation

## Overview

Sift is a comprehensive forensic intelligence correlation platform designed to bridge the gap between digital forensic analysis and open-source intelligence (OSINT) collection. The system correlates temporal, spatial, and content-based patterns between forensic evidence and publicly available data to provide investigators with enhanced situational awareness and context.

## Architecture

### Core Components

#### 1. Configuration Management (`src/config.py`)
Central configuration system using environment variables to ensure no hardcoded values throughout the application. Key configuration areas:

- **Database Configuration**: SQLite database path and settings
- **Flask Web Server**: Host, port, debug mode, and secret key
- **OSINT API Keys**: Twitter, Reddit, News APIs, and Google search
- **LLM Integration**: Ollama host, model selection, and analysis parameters
- **Web Search**: Multiple search engines (Google API, SerpApi, DuckDuckGo)
- **Forensic Analysis**: Timezone handling and file processing settings

#### 2. Database Layer (`src/database.py`)
SQLite-based data persistence with the following schema:

- **investigations**: Core investigation metadata
- **forensic_events**: Filesystem timeline events from disk images
- **osint_data**: Collected open-source intelligence items
- **correlations**: Computed relationships between forensic and OSINT data

Implements comprehensive foreign key relationships and cascading deletes for data integrity.

#### 3. Forensic Analysis Engine (`src/forensics.py`)
Digital forensic evidence processing using pytsk3 library for disk image analysis:

- **Supported Formats**: E01 (Expert Witness), DD/RAW disk images
- **Timeline Generation**: Extracts filesystem metadata, timestamps, and file attributes
- **Evidence Processing**: Handles large disk images with efficient streaming
- **Timezone Support**: Configurable timezone conversion for accurate temporal correlation

#### 4. OSINT Collection System (`src/osint.py`)
Multi-source intelligence gathering with graceful degradation:

- **Twitter API Integration**: Tweet collection using tweepy library
- **Reddit Integration**: Subreddit monitoring with praw library
- **News API Collection**: Multiple news sources via News API
- **Web Intelligence Integration**: LLM-powered search query generation

#### 5. Advanced Web Intelligence (`src/advanced_web_intelligence.py`)
Enhanced web search and analysis capabilities:

- **Multi-Engine Search**: Google API, SerpApi, unofficial Google search, DuckDuckGo
- **LLM Query Generation**: Context-aware search query creation based on forensic evidence
- **Content Extraction**: Multi-stage content processing with newspaper3k, readability
- **Browser Automation**: Selenium-based dynamic content extraction for complex sites
- **Quality Filtering**: Advanced deduplication and relevance scoring

#### 6. LLM Integration (`src/llm_client.py`)
Local Ollama model integration for privacy-preserving analysis:

- **Model Management**: Automatic model detection and fallback handling
- **Content Analysis**: Forensic evidence interpretation and pattern recognition
- **Correlation Analysis**: LLM-enhanced correlation insight generation
- **Investigation Summaries**: Automated report generation and trend analysis

#### 7. Correlation Engine (`src/correlation.py`)
Multi-dimensional correlation analysis combining traditional algorithms with LLM insights:

- **Temporal Correlation**: Time-based proximity analysis with configurable thresholds
- **Spatial Correlation**: Geographic distance calculation using haversine formula
- **Content Relevance**: Text similarity analysis using TF-IDF and semantic matching
- **LLM Enhancement**: Pattern recognition and contextual analysis for complex correlations

#### 8. Model Management (`src/ollama_manager.py`)
Comprehensive Ollama model management system:

- **Model Discovery**: Automatic detection of installed and recommended models
- **Download Management**: Model pulling with progress tracking
- **Performance Testing**: Model capability validation and benchmarking
- **Active Model Selection**: Runtime model switching for different analysis tasks

#### 9. Web Interface (`src/webapp.py`)
Flask-based web interface providing complete investigation management:

- **Investigation CRUD**: Create, read, update, delete investigations with full data cascade
- **Evidence Upload**: Forensic image processing with progress tracking
- **OSINT Collection**: Multi-source intelligence gathering with parameter control
- **Correlation Analysis**: Interactive correlation execution with real-time results
- **Visualization**: Timeline, map, and analytics views with Plotly integration
- **Model Management**: Web-based Ollama model administration

## Technical Decisions and Rationale

### Database Choice: SQLite
**Decision**: Use SQLite for data persistence
**Rationale**: 
- Single-file deployment simplicity
- No external database server requirements
- ACID compliance for data integrity
- Full SQL support for complex queries
- Sufficient performance for investigative workloads

### LLM Integration: Local Ollama
**Decision**: Use local Ollama models instead of cloud APIs
**Rationale**:
- **Privacy**: Forensic data never leaves the local environment
- **Security**: No external API dependencies or data exposure
- **Cost Control**: No per-token charges for analysis
- **Customization**: Ability to fine-tune models for forensic contexts
- **Availability**: Works in air-gapped or restricted environments

### Web Search Strategy: Multiple Engines
**Decision**: Implement multiple search engines with intelligent fallbacks
**Rationale**:
- **Redundancy**: Different engines may return different results
- **Rate Limiting**: Distribute requests across multiple services
- **Quality**: Combine results from different sources for better coverage
- **Reliability**: Graceful degradation when individual services are unavailable

### Configuration Management: Environment Variables
**Decision**: Use environment variables for all configuration
**Rationale**:
- **Security**: No secrets committed to version control
- **Flexibility**: Easy deployment across different environments
- **Standards Compliance**: Follows 12-factor application principles
- **Docker Compatibility**: Native container environment integration

### Content Extraction: Multi-Stage Pipeline
**Decision**: Implement fallback content extraction methods
**Rationale**:
- **Reliability**: Different sites require different extraction approaches
- **Quality**: Multiple methods improve content extraction accuracy
- **Performance**: Efficient methods tried first, complex methods as fallbacks
- **Maintainability**: Modular design allows easy addition of new extractors

## Data Flow

### Investigation Lifecycle
1. **Investigation Creation**: Basic metadata and scope definition
2. **Evidence Upload**: Forensic disk image processing and timeline generation
3. **OSINT Collection**: Multi-source intelligence gathering based on investigation parameters
4. **Web Intelligence**: LLM-powered search query generation and advanced web content extraction
5. **Correlation Analysis**: Multi-dimensional correlation computation with LLM enhancement
6. **Visualization**: Timeline, geographic, and analytical visualization generation
7. **Export**: Complete investigation data export in JSON format

### Correlation Algorithm
1. **Temporal Analysis**: Calculate time proximity between forensic events and OSINT items
2. **Spatial Analysis**: Compute geographic distance when location data is available
3. **Content Analysis**: Perform text similarity analysis using TF-IDF and semantic matching
4. **Scoring**: Combine individual metrics into overall correlation strength
5. **LLM Enhancement**: Generate contextual insights and pattern recognition
6. **Ranking**: Sort correlations by strength and relevance for investigator review

## Performance Considerations

### Database Optimization
- **Indexing**: Strategic indexes on timestamp and correlation strength columns
- **Connection Management**: Context manager pattern for proper connection handling
- **Batch Operations**: Bulk inserts for large forensic timeline data
- **Query Optimization**: Efficient SQL queries with proper JOIN operations

### Memory Management
- **Streaming Processing**: Large forensic images processed in chunks
- **Lazy Loading**: OSINT data loaded on-demand to reduce memory footprint
- **Connection Pooling**: Efficient database connection reuse
- **Garbage Collection**: Explicit cleanup of large objects after processing

### Scalability
- **Asynchronous Processing**: Background tasks for long-running operations
- **Caching**: Intelligent caching of expensive operations (geocoding, content extraction)
- **Pagination**: Large dataset pagination for web interface performance
- **Compression**: Efficient storage of large text content in database

## Security Considerations

### Data Protection
- **Local Processing**: All sensitive data remains on local infrastructure
- **No Cloud Dependencies**: LLM analysis performed locally via Ollama
- **Access Control**: Session-based authentication for web interface
- **Input Validation**: Comprehensive validation of file uploads and user inputs

### API Security
- **Rate Limiting**: Implement rate limiting for OSINT API calls
- **Key Management**: Secure storage of API keys via environment variables
- **Error Handling**: Prevent information leakage through error messages
- **HTTPS Support**: TLS encryption for web interface communications

## Deployment

### System Requirements
- **Python 3.8+**: Core runtime environment
- **Ollama**: Local LLM inference engine
- **SQLite**: Database engine (included with Python)
- **Modern Web Browser**: For web interface access

### Dependencies
- **Core**: Flask, sqlite3, logging, datetime
- **Forensics**: pytsk3 for disk image analysis
- **OSINT**: tweepy (Twitter), praw (Reddit), requests (APIs)
- **Web Intelligence**: googlesearch-python, requests-cache, selenium
- **Analysis**: numpy, scikit-learn, plotly, folium
- **Content Processing**: newspaper3k, readability-lxml, BeautifulSoup4

### Installation Process
1. **Environment Setup**: Create Python virtual environment
2. **Dependencies**: Install required packages via pip
3. **Ollama Installation**: Install and configure local LLM engine
4. **Configuration**: Set environment variables for APIs and settings
5. **Database Initialization**: Automatic schema creation on first run
6. **Service Start**: Launch Flask web interface

## Testing and Quality Assurance

### Test Scenarios
- **Forensic Processing**: Test with various disk image formats and sizes
- **OSINT Integration**: Verify data collection from multiple sources
- **Correlation Accuracy**: Validate correlation algorithms with known datasets
- **LLM Integration**: Test model availability and response handling
- **Web Interface**: Comprehensive UI/UX testing across browsers

### Error Handling
- **Graceful Degradation**: System continues to function when individual components fail
- **Comprehensive Logging**: Detailed logging for debugging and audit trails
- **User Feedback**: Clear error messages and progress indicators
- **Recovery Mechanisms**: Automatic retry logic for transient failures

## Future Enhancements

### Planned Features
- **Real-time Monitoring**: Live OSINT feed monitoring and alerting
- **Machine Learning**: Advanced pattern recognition using custom trained models
- **Distributed Processing**: Multi-node deployment for large-scale investigations
- **Advanced Visualization**: 3D timeline visualization and network analysis
- **Report Generation**: Automated investigative report generation with findings

### Integration Opportunities
- **SIEM Integration**: Export correlations to security information systems
- **Threat Intelligence**: Integration with commercial threat intelligence feeds
- **Case Management**: Integration with legal case management systems
- **Mobile Interface**: Mobile-responsive design for field investigations