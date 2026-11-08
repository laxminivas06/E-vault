import logging
from math import radians, sin, cos, sqrt, atan2
from config import Config
from services.data_store import db

logger = logging.getLogger(__name__)

class LocationService:
    @staticmethod
    def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate great-circle distance between two points in kilometers."""
        r = 6371.0  # Earth's radius in km
        phi1, phi2 = radians(lat1), radians(lat2)
        delta_phi = radians(lat2 - lat1)
        delta_lambda = radians(lon2 - lon1)

        a = sin(delta_phi / 2.0) ** 2 + cos(phi1) * cos(phi2) * sin(delta_lambda / 2.0) ** 2
        c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a))
        return r * c

    @staticmethod
    def is_point_in_polygon(lat: float, lon: float, polygon_coords: list) -> bool:
        """Ray-casting algorithm to determine if point is inside a polygon."""
        if not polygon_coords or len(polygon_coords) < 3:
            return False

        inside = False
        n = len(polygon_coords)
        p1x, p1y = polygon_coords[0]

        for i in range(1, n + 1):
            p2x, p2y = polygon_coords[i % n]
            if lat > min(p1x, p2x):
                if lat <= max(p1x, p2x):
                    if lon <= max(p1y, p2y):
                        if p1x != p2x:
                            xinters = (lat - p1x) * (p2y - p1y) / (p2x - p1x) + p1y
                        if p1y == p2y or lon <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y

        return inside

    @classmethod
    def validate_coordinates(cls, lat, lon):
        """Ensure latitude and longitude are valid numeric values in geographic range."""
        try:
            latitude = float(lat)
            longitude = float(lon)
        except (ValueError, TypeError):
            return None, None

        if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0):
            return None, None

        return latitude, longitude

    @classmethod
    def check_user_location(cls, user_lat: float, user_lon: float):
        """
        Verify if the given coordinates fall inside any configured boundary
        or institutional campus zone. Returns (is_allowed, location_name).
        """
        lat, lon = cls.validate_coordinates(user_lat, user_lon)
        if lat is None or lon is None:
            return False, "Invalid Coordinates"

        boundaries = db.get_boundaries()

        # Check configured dynamic boundaries first
        for b in boundaries:
            b_type = b.get('type', 'circle')
            name = b.get('name') or Config.DEFAULT_CAMPUS_NAME

            if b_type == 'circle':
                try:
                    b_lat = float(b['latitude'])
                    b_lon = float(b['longitude'])
                    radius_km = float(b.get('radius_km', 1.0))
                    dist = cls.calculate_distance_km(lat, lon, b_lat, b_lon)
                    if dist <= radius_km:
                        return True, name
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning(f"Error checking circle boundary: {e}")
                    continue

            elif b_type == 'rectangle':
                try:
                    south = float(b['south'])
                    north = float(b['north'])
                    west = float(b['west'])
                    east = float(b['east'])
                    if south <= lat <= north and west <= lon <= east:
                        return True, name
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning(f"Error checking rectangle boundary: {e}")
                    continue

            elif b_type == 'polygon':
                try:
                    coords = b.get('coordinates', [])
                    if cls.is_point_in_polygon(lat, lon, coords):
                        return True, name
                except Exception as e:
                    logger.warning(f"Error checking polygon boundary: {e}")
                    continue

        # Check fallback allowed locations
        for loc in Config.ALLOWED_LOCATIONS:
            try:
                dist = cls.calculate_distance_km(lat, lon, loc['latitude'], loc['longitude'])
                if dist <= loc['radius_km']:
                    return True, loc['name']
            except Exception as e:
                logger.warning(f"Error checking default allowed location: {e}")

        return False, None

