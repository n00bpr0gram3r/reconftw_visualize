const API_BASE_URL = 'http://localhost:3001/api';

export interface HostData {
  url: string;
  title: string;
  webserver: string;
  content_type: string;
  screenshot?: string; // Optional screenshot path
  // Add other fields from web_full_info.txt as needed
}

export const fetchScans = async (): Promise<string[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: string[] = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching scans:", error);
    return [];
  }
};

export const fetchSubdomains = async (scanName: string): Promise<string[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanName}/subdomains`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: string[] = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching subdomains for ${scanName}:`, error);
    return [];
  }
};

export const fetchHosts = async (scanName: string): Promise<HostData[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanName}/hosts`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: HostData[] = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching hosts for ${scanName}:`, error);
    return [];
  }
};

export interface VulnerabilityData {
  "template-id": string;
  info: {
    name: string;
    author: string[];
    severity: string;
    description: string;
    reference: string[];
    tags: string[];
  };
  "matched-at": string;
  // Add other fields from Nuclei JSON output as needed
}

export const fetchVulnerabilities = async (scanName: string): Promise<VulnerabilityData[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanName}/vulnerabilities`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: VulnerabilityData[] = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching vulnerabilities for ${scanName}:`, error);
    return [];
  }
};

export interface OsintData {
  emails: string[];
  dorks: string[];
}

export const fetchOsint = async (scanName: string): Promise<OsintData> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanName}/osint`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: OsintData = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching OSINT data for ${scanName}:`, error);
    return { emails: [], dorks: [] }; // Return empty object on error
  }
};

export interface PortData {
  ip: string;
  hostnames: string[];
  portid: string;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
}

export const fetchPorts = async (scanName: string): Promise<PortData[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanName}/ports`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data: PortData[] = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching ports for ${scanName}:`, error);
    return [];
  }
};
