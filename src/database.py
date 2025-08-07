import sqlite3
import json
import logging
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    evidence_path TEXT,
                    location TEXT,
                    timezone TEXT DEFAULT 'UTC',
                    created_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS forensic_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    inode INTEGER,
                    file_type TEXT,
                    permissions INTEGER,
                    uid INTEGER,
                    gid INTEGER,
                    metadata TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS osint_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER,
                    timestamp DATETIME NOT NULL,
                    source TEXT NOT NULL,
                    content TEXT NOT NULL,
                    author TEXT,
                    location TEXT,
                    coordinates_lat REAL,
                    coordinates_lon REAL,
                    url TEXT,
                    engagement_data TEXT,
                    metadata TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER,
                    forensic_event_id INTEGER,
                    osint_data_id INTEGER,
                    correlation_strength REAL NOT NULL,
                    temporal_proximity REAL,
                    spatial_proximity REAL,
                    content_relevance REAL,
                    created_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id),
                    FOREIGN KEY (forensic_event_id) REFERENCES forensic_events (id),
                    FOREIGN KEY (osint_data_id) REFERENCES osint_data (id)
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_forensic_timestamp 
                ON forensic_events(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_osint_timestamp 
                ON osint_data(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_correlations_strength 
                ON correlations(correlation_strength)
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_investigation(self, name, description=None, evidence_path=None, location=None, timezone='UTC'):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO investigations (name, description, evidence_path, location, timezone)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, description, evidence_path, location, timezone))
            investigation_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"Created investigation '{name}' with ID {investigation_id}")
            return investigation_id
    
    def get_investigations(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM investigations ORDER BY created_timestamp DESC')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_investigation(self, investigation_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM investigations WHERE id = ?', (investigation_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def save_forensic_events(self, investigation_id, events):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for event in events:
                cursor.execute('''
                    INSERT INTO forensic_events 
                    (investigation_id, timestamp, event_type, file_path, file_size, 
                     inode, file_type, permissions, uid, gid, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    investigation_id,
                    event['timestamp'],
                    event['event_type'],
                    event['file_path'],
                    event.get('file_size'),
                    event.get('inode'),
                    event.get('file_type'),
                    event.get('permissions'),
                    event.get('uid'),
                    event.get('gid'),
                    json.dumps({k: v for k, v in event.items() if k not in [
                        'timestamp', 'event_type', 'file_path', 'file_size', 
                        'inode', 'file_type', 'permissions', 'uid', 'gid'
                    ]})
                ))
            
            conn.commit()
            logger.info(f"Saved {len(events)} forensic events for investigation {investigation_id}")
    
    def save_osint_data(self, investigation_id, osint_items):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for item in osint_items:
                coords = item.get('coordinates', {})
                cursor.execute('''
                    INSERT INTO osint_data 
                    (investigation_id, timestamp, source, content, author, location,
                     coordinates_lat, coordinates_lon, url, engagement_data, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    investigation_id,
                    item['timestamp'],
                    item['source'],
                    item['content'],
                    item.get('author'),
                    item.get('location'),
                    coords.get('lat') if coords else None,
                    coords.get('lon') if coords else None,
                    item.get('url'),
                    json.dumps(item.get('engagement', {})),
                    json.dumps(item.get('data', {}))
                ))
            
            conn.commit()
            logger.info(f"Saved {len(osint_items)} OSINT items for investigation {investigation_id}")
    
    def save_correlations(self, investigation_id, correlations):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            forensic_event_map = self._get_forensic_event_map(investigation_id)
            osint_data_map = self._get_osint_data_map(investigation_id)
            
            for correlation in correlations:
                forensic_event = correlation['forensic_event']
                forensic_key = f"{forensic_event['timestamp']}_{forensic_event['file_path']}"
                forensic_event_id = forensic_event_map.get(forensic_key)
                
                if not forensic_event_id:
                    continue
                
                for osint_corr in correlation['osint_correlations']:
                    osint_item = osint_corr['osint_item']
                    osint_key = f"{osint_item['timestamp']}_{osint_item['source']}_{osint_item['content'][:50]}"
                    osint_data_id = osint_data_map.get(osint_key)
                    
                    if not osint_data_id:
                        continue
                    
                    spatial_prox = osint_corr.get('spatial_proximity', {})
                    cursor.execute('''
                        INSERT INTO correlations 
                        (investigation_id, forensic_event_id, osint_data_id, 
                         correlation_strength, temporal_proximity, spatial_proximity, content_relevance)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        investigation_id,
                        forensic_event_id,
                        osint_data_id,
                        correlation['correlation_strength'],
                        osint_corr['temporal_proximity'],
                        spatial_prox.get('distance_km') if spatial_prox else None,
                        osint_corr['content_relevance']
                    ))
            
            conn.commit()
            logger.info(f"Saved correlations for investigation {investigation_id}")
    
    def _get_forensic_event_map(self, investigation_id):
        event_map = {}
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, file_path FROM forensic_events 
                WHERE investigation_id = ?
            ''', (investigation_id,))
            
            for row in cursor.fetchall():
                key = f"{row['timestamp']}_{row['file_path']}"
                event_map[key] = row['id']
        
        return event_map
    
    def _get_osint_data_map(self, investigation_id):
        osint_map = {}
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, source, content FROM osint_data 
                WHERE investigation_id = ?
            ''', (investigation_id,))
            
            for row in cursor.fetchall():
                key = f"{row['timestamp']}_{row['source']}_{row['content'][:50]}"
                osint_map[key] = row['id']
        
        return osint_map
    
    def get_forensic_events(self, investigation_id, limit=None, start_time=None, end_time=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM forensic_events WHERE investigation_id = ?'
            params = [investigation_id]
            
            if start_time:
                query += ' AND timestamp >= ?'
                params.append(start_time)
            
            if end_time:
                query += ' AND timestamp <= ?'
                params.append(end_time)
            
            query += ' ORDER BY timestamp'
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            events = []
            
            for row in cursor.fetchall():
                event = dict(row)
                if event['metadata']:
                    event.update(json.loads(event['metadata']))
                events.append(event)
            
            return events
    
    def get_osint_data(self, investigation_id, limit=None, source=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM osint_data WHERE investigation_id = ?'
            params = [investigation_id]
            
            if source:
                query += ' AND source = ?'
                params.append(source)
            
            query += ' ORDER BY timestamp'
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            items = []
            
            for row in cursor.fetchall():
                item = dict(row)
                
                if item['coordinates_lat'] and item['coordinates_lon']:
                    item['coordinates'] = {
                        'lat': item['coordinates_lat'],
                        'lon': item['coordinates_lon']
                    }
                
                if item['engagement_data']:
                    item['engagement'] = json.loads(item['engagement_data'])
                
                if item['metadata']:
                    item['data'] = json.loads(item['metadata'])
                
                items.append(item)
            
            return items
    
    def get_correlations(self, investigation_id, min_strength=0.0, limit=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT c.*, fe.file_path, fe.timestamp as forensic_timestamp,
                       od.content as osint_content, od.source as osint_source
                FROM correlations c
                JOIN forensic_events fe ON c.forensic_event_id = fe.id
                JOIN osint_data od ON c.osint_data_id = od.id
                WHERE c.investigation_id = ? AND c.correlation_strength >= ?
                ORDER BY c.correlation_strength DESC
            '''
            
            params = [investigation_id, min_strength]
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_investigation_statistics(self, investigation_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as count FROM forensic_events WHERE investigation_id = ?', 
                          (investigation_id,))
            forensic_count = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM osint_data WHERE investigation_id = ?', 
                          (investigation_id,))
            osint_count = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM correlations WHERE investigation_id = ?', 
                          (investigation_id,))
            correlation_count = cursor.fetchone()['count']
            
            cursor.execute('''
                SELECT AVG(correlation_strength) as avg_strength 
                FROM correlations WHERE investigation_id = ?
            ''', (investigation_id,))
            avg_strength = cursor.fetchone()['avg_strength'] or 0.0
            
            return {
                'forensic_events': forensic_count,
                'osint_items': osint_count,
                'correlations': correlation_count,
                'avg_correlation_strength': avg_strength
            }
    
    def delete_investigation(self, investigation_id):
        # nuke everything related to this investigation
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # correlations have to go first or SQLite gets mad
            cursor.execute('DELETE FROM correlations WHERE investigation_id = ?', (investigation_id,))
            
            # clean up the forensic stuff
            cursor.execute('DELETE FROM forensic_events WHERE investigation_id = ?', (investigation_id,))
            
            # and the OSINT data too
            cursor.execute('DELETE FROM osint_data WHERE investigation_id = ?', (investigation_id,))
            
            # now we can delete the main investigation
            cursor.execute('DELETE FROM investigations WHERE id = ?', (investigation_id,))
            
            if cursor.rowcount == 0:
                return False
            
            conn.commit()
            logger.info(f"Deleted investigation {investigation_id} and all associated data")
            return True