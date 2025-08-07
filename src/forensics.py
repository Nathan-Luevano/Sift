import logging
import hashlib
from datetime import datetime
from dateutil import tz
import os
import struct

logger = logging.getLogger(__name__)

# need to check if pytsk3 is installed
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False
    logger.warning("pytsk3 not available - forensic image processing will be limited")

class ForensicAnalyzer:
    def __init__(self):
        self.timeline_events = []
        
    def parse_evidence_file(self, evidence_path, timezone_str='UTC'):
        try:
            # make sure pytsk3 is actually available
            if not PYTSK3_AVAILABLE:
                logger.error("Cannot process forensic images: pytsk3 library is not installed")
                raise ImportError("pytsk3 library is required for forensic image processing. Please install it with: apt install python3-pytsk3 or pip install pytsk3")
            
            # basic file validation first
            if not os.path.exists(evidence_path):
                raise FileNotFoundError(f"Evidence file not found: {evidence_path}")
            
            file_size = os.path.getsize(evidence_path)
            if file_size < 512:  # way too small for any real forensic image
                raise ValueError(f"Evidence file is too small ({file_size} bytes). Minimum size is 512 bytes for a valid forensic image.")
            
            logger.info(f"Processing evidence file: {evidence_path} ({file_size} bytes)")
            
            timezone = tz.gettz(timezone_str)
            
            if evidence_path.endswith('.E01') or evidence_path.endswith('.e01'):
                return self._parse_ewf_image(evidence_path, timezone)
            else:
                return self._parse_raw_image(evidence_path, timezone)
                
        except Exception as e:
            logger.error(f"Error parsing evidence file {evidence_path}: {e}")
            raise  # let the web interface handle the error properly
    
    def _parse_ewf_image(self, ewf_path, timezone):
        try:
            img_info = pytsk3.Img_Info(ewf_path)
            return self._extract_filesystem_timeline(img_info, timezone)
        except Exception as e:
            logger.error(f"Error parsing EWF image: {e}")
            return []
    
    def _parse_raw_image(self, raw_path, timezone):
        try:
            img_info = pytsk3.Img_Info(raw_path)
            return self._extract_filesystem_timeline(img_info, timezone)
        except Exception as e:
            logger.error(f"Error parsing raw image: {e}")
            return []
    
    def _extract_filesystem_timeline(self, img_info, timezone):
        timeline_events = []
        
        try:
            logger.debug("Attempting to parse volume/partition table")
            partitions = pytsk3.Volume_Info(img_info)
            logger.info(f"Found {len(list(partitions))} partitions")
            
            for partition in partitions:
                logger.debug(f"Processing partition: start={partition.start}, length={partition.len}, type={partition.desc.decode('utf-8', errors='ignore')}")
                if partition.len > 2048:
                    try:
                        fs_info = pytsk3.FS_Info(img_info, offset=partition.start * 512)
                        logger.info(f"Successfully opened filesystem at partition offset {partition.start}")
                        events = self._process_filesystem(fs_info, timezone, partition.start)
                        timeline_events.extend(events)
                        logger.info(f"Extracted {len(events)} events from partition at offset {partition.start}")
                    except Exception as e:
                        logger.warning(f"Could not process partition at offset {partition.start}: {e}")
                        continue
                else:
                    logger.debug(f"Skipping small partition at offset {partition.start} (length: {partition.len})")
                        
        except Exception as e:
            logger.info(f"No partition table found ({e}), trying to parse as raw filesystem")
            try:
                fs_info = pytsk3.FS_Info(img_info)
                logger.info("Successfully opened raw filesystem")
                events = self._process_filesystem(fs_info, timezone, 0)
                timeline_events.extend(events)
                logger.info(f"Extracted {len(events)} events from raw filesystem")
            except Exception as e2:
                logger.error(f"Could not process image as filesystem: {e2}")
                
        logger.info(f"Total timeline events extracted: {len(timeline_events)}")
        return sorted(timeline_events, key=lambda x: x['timestamp'])
    
    def _process_filesystem(self, fs_info, timezone, partition_offset):
        events = []
        
        try:
            logger.debug(f"Opening root directory for filesystem")
            root_dir = fs_info.open_dir(path="/")
            logger.debug("Successfully opened root directory")
            events.extend(self._process_directory(fs_info, root_dir, "/", timezone))
            logger.debug(f"Processed root directory, found {len(events)} events")
        except Exception as e:
            logger.error(f"Error processing root directory: {e}")
            
        return events
    
    def _process_directory(self, fs_info, directory, path, timezone, max_depth=10):
        events = []
        
        if max_depth <= 0:
            logger.debug(f"Max depth reached for directory {path}")
            return events
            
        try:
            file_count = 0
            logger.debug(f"Processing directory: {path}")
            
            for f in directory:
                if f.info.name.name in [b".", b".."]:
                    continue
                
                file_count += 1    
                filename = f.info.name.name.decode('utf-8', errors='ignore')
                full_path = os.path.join(path, filename).replace('\\', '/')
                
                logger.debug(f"Processing file: {full_path}")
                file_events = self._extract_file_timestamps(f, full_path, timezone)
                events.extend(file_events)
                logger.debug(f"Extracted {len(file_events)} events from {full_path}")
                
                if f.info.meta and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        subdir = fs_info.open_dir(inode=f.info.meta.addr)
                        subdir_events = self._process_directory(
                            fs_info, subdir, full_path, timezone, max_depth - 1
                        )
                        events.extend(subdir_events)
                        logger.debug(f"Extracted {len(subdir_events)} events from subdirectory {full_path}")
                    except Exception as e:
                        logger.debug(f"Could not process subdirectory {full_path}: {e}")
            
            logger.debug(f"Processed {file_count} files in directory {path}, total events: {len(events)}")
                        
        except Exception as e:
            logger.error(f"Error processing directory {path}: {e}")
            
        return events
    
    def _extract_file_timestamps(self, file_obj, path, timezone):
        events = []
        
        try:
            if not file_obj.info.meta:
                logger.debug(f"No metadata available for {path}")
                return events
            
            meta = file_obj.info.meta
            file_size = meta.size if meta.size else 0
            
            logger.debug(f"File {path}: size={file_size}, type={meta.type}")
            
            timestamps = {
                'modified': meta.mtime,
                'accessed': meta.atime,
                'created': meta.crtime,
                'changed': meta.ctime
            }
            
            logger.debug(f"Raw timestamps for {path}: {timestamps}")
            
            for event_type, timestamp in timestamps.items():
                logger.debug(f"Processing {event_type} timestamp: {timestamp}")
                if timestamp and timestamp > 0:
                    dt = datetime.fromtimestamp(timestamp, tz=timezone)
                    logger.debug(f"Created datetime: {dt}")
                    
                    events.append({
                        'timestamp': dt,
                        'event_type': event_type,
                        'file_path': path,
                        'file_size': file_size,
                        'inode': meta.addr,
                        'file_type': self._get_file_type(meta.type),
                        'permissions': meta.mode if hasattr(meta, 'mode') else None,
                        'uid': meta.uid if hasattr(meta, 'uid') else None,
                        'gid': meta.gid if hasattr(meta, 'gid') else None
                    })
                else:
                    logger.debug(f"Skipping {event_type} timestamp for {path}: invalid value ({timestamp})")
            
            logger.debug(f"Generated {len(events)} events for {path}")
                    
        except Exception as e:
            logger.debug(f"Error extracting timestamps for {path}: {e}")
            
        return events
    
    def _get_file_type(self, tsk_type):
        type_mapping = {
            pytsk3.TSK_FS_META_TYPE_REG: 'file',
            pytsk3.TSK_FS_META_TYPE_DIR: 'directory',
            pytsk3.TSK_FS_META_TYPE_LNK: 'symlink',
            pytsk3.TSK_FS_META_TYPE_CHR: 'char_device',
            pytsk3.TSK_FS_META_TYPE_BLK: 'block_device',
            pytsk3.TSK_FS_META_TYPE_FIFO: 'fifo',
            pytsk3.TSK_FS_META_TYPE_SOCK: 'socket'
        }
        return type_mapping.get(tsk_type, 'unknown')
    
    def filter_timeline_by_timerange(self, events, start_time, end_time):
        filtered = []
        for event in events:
            if start_time <= event['timestamp'] <= end_time:
                filtered.append(event)
        return filtered
    
    def filter_timeline_by_path(self, events, path_pattern):
        filtered = []
        for event in events:
            if path_pattern.lower() in event['file_path'].lower():
                filtered.append(event)
        return filtered
    
    def get_timeline_summary(self, events):
        if not events:
            return {}
            
        return {
            'total_events': len(events),
            'start_time': min(events, key=lambda x: x['timestamp'])['timestamp'],
            'end_time': max(events, key=lambda x: x['timestamp'])['timestamp'],
            'event_types': list(set(event['event_type'] for event in events)),
            'file_types': list(set(event['file_type'] for event in events)),
            'unique_files': len(set(event['file_path'] for event in events))
        }