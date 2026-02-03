from typing import List, Optional
import pandas as pd


class ProbeSelector:
    """
    Fluent interface for selecting and filtering RIPE Atlas probes.
    Wraps a pandas DataFrame containing probe data.
    """

    def __init__(self, data: pd.DataFrame):
        self._data = data

    @classmethod
    def from_csv(cls, path: str = "ripe_probes.csv") -> "ProbeSelector":
        """Load probes from a CSV file."""
        df = pd.read_csv(path)
        return cls(df)

    def filter_by_status(self, status_name: str) -> "ProbeSelector":
        """Filter by status name."""
        return ProbeSelector(self._data[self._data["status_name"] == status_name])

    def connected(self) -> "ProbeSelector":
        """Filter to only include currently connected probes."""
        return self.filter_by_status("Connected")

    def from_country(self, country_code: str) -> "ProbeSelector":
        """Filter probes by country code (e.g., 'US', 'CL')."""
        return self.from_countries([country_code])

    def from_countries(self, country_codes: List[str]) -> "ProbeSelector":
        """Filter probes by a list of country codes."""
        return ProbeSelector(self._data[self._data["country_code"].isin(country_codes)])

    def with_asn(self, asn: int, ip_version: str = "v4") -> "ProbeSelector":
        """Filter probes by ASN."""
        column = f"asn_{ip_version}"
        return ProbeSelector(self._data[self._data[column] == asn])

    def has_ipv4(self) -> "ProbeSelector":
        """Filter to only include probes that have an IPv4 address."""
        return ProbeSelector(
            self._data[
                self._data["address_v4"].notna() & (self._data["address_v4"] != "")
            ]
        )

    def has_ipv6(self) -> "ProbeSelector":
        """Filter to only include probes that have an IPv6 address."""
        return ProbeSelector(
            self._data[
                self._data["address_v6"].notna() & (self._data["address_v6"] != "")
            ]
        )

    def public(self) -> "ProbeSelector":
        """Filter to only include public probes."""
        return ProbeSelector(self._data[self._data["is_public"] == "t"])

    def anchors(self) -> "ProbeSelector":
        """Filter to only include anchor probes."""
        return ProbeSelector(self._data[self._data["is_anchor"] == "t"])

    def within_bounds(
        self,
        min_lon: Optional[float] = None,
        max_lon: Optional[float] = None,
        min_lat: Optional[float] = None,
        max_lat: Optional[float] = None,
    ) -> "ProbeSelector":
        """Filter probes by geographic bounds."""
        filtered = self._data.copy()
        if min_lon is not None:
            filtered = filtered[filtered["lon"] >= min_lon]
        if max_lon is not None:
            filtered = filtered[filtered["lon"] <= max_lon]
        if min_lat is not None:
            filtered = filtered[filtered["lat"] >= min_lat]
        if max_lat is not None:
            filtered = filtered[filtered["lat"] <= max_lat]
        return ProbeSelector(filtered)

    def limit(self, n: int) -> "ProbeSelector":
        """Limit the number of probes (taking the top N)."""
        return ProbeSelector(self._data.head(n))

    def get_ids(self) -> List[int]:
        """Return the list of probe IDs."""
        return self._data["id"].tolist()

    def result_count(self) -> int:
        """Return the number of probes currently selected."""
        return len(self._data)

    def to_dataframe(self) -> pd.DataFrame:
        """Return the underlying DataFrame."""
        return self._data
