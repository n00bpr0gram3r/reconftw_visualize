import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { Container, Typography, Box, CircularProgress, Grid, Card, CardContent, CardMedia, List, ListItem, ListItemText, Tabs, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, TableSortLabel, FormControl, InputLabel, Select, MenuItem, OutlinedInput, Checkbox } from '@mui/material';
import { fetchSubdomains, fetchHosts, fetchVulnerabilities, fetchOsint, fetchPorts } from '../services/api';
import type { HostData, VulnerabilityData, OsintData, PortData } from '../services/api';

type Order = 'asc' | 'desc';

function descendingComparator<T>(a: T, b: T, orderBy: keyof T) {
  if (b[orderBy] < a[orderBy]) {
    return -1;
  }
  if (b[orderBy] > a[orderBy]) {
    return 1;
  }
  return 0;
}

function getComparator<Key extends keyof any>(
  order: Order,
  orderBy: Key,
): (a: { [key in Key]: number | string }, b: { [key in Key]: number | string }) => number {
  return order === 'desc'
    ? (a, b) => descendingComparator(a, b, orderBy)
    : (a, b) => -descendingComparator(a, b, orderBy);
}

function stableSort<T>(array: readonly T[], comparator: (a: T, b: T) => number) {
  const stabilizedThis = array.map((el, index) => [el, index] as [T, number]);
  stabilizedThis.sort((a, b) => {
    const order = comparator(a[0], b[0]);
    if (order !== 0) {
      return order;
    }
    return a[1] - b[1];
  });
  return stabilizedThis.map((el) => el[0]);
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function ScanDetail() {
  const { scanName } = useParams<{ scanName: string }>();
  const [subdomains, setSubdomains] = useState<string[]>([]);
  const [hosts, setHosts] = useState<HostData[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityData[]>([]);
  const [osint, setOsint] = useState<OsintData>({ emails: [], dorks: [] });
  const [ports, setPorts] = useState<PortData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);

  // State for vulnerabilities table sorting
  const [vulnOrder, setVulnOrder] = useState<Order>('asc');
  const [vulnOrderBy, setVulnOrderBy] = useState<keyof VulnerabilityData['info'] | 'template-id' | 'matched-at'>('severity');

  // State for ports table sorting
  const [portsOrder, setPortsOrder] = useState<Order>('asc');
  const [portsOrderBy, setPortsOrderBy] = useState<keyof PortData>('portid');
  const [selectedPorts, setSelectedPorts] = useState<string[]>([]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleVulnSortRequest = (property: keyof VulnerabilityData['info'] | 'template-id' | 'matched-at') => {
    const isAsc = vulnOrderBy === property && vulnOrder === 'asc';
    setVulnOrder(isAsc ? 'desc' : 'asc');
    setVulnOrderBy(property);
  };

  const handlePortsSortRequest = (property: keyof PortData) => {
    const isAsc = portsOrderBy === property && portsOrder === 'asc';
    setPortsOrder(isAsc ? 'desc' : 'asc');
    setPortsOrderBy(property);
  };

  const handleSelectedPortsChange = (event: React.ChangeEvent<{ value: unknown }>) => {
    const {
      target: { value },
    } = event;
    setSelectedPorts(
      typeof value === 'string' ? value.split(',') : value as string[],
    );
  };

  const renderDork = (dork: string) => {
    const match = dork.match(/\((.*?)\)/);
    if (match && match[1]) {
      const url = match[1];
      const text = dork.replace(match[0], '').trim();
      return (
        <a href={url} target="_blank" rel="noopener noreferrer">
          {text}
        </a>
      );
    }
    return dork;
  };

  const sortedVulnerabilities = useMemo(() => {
    const comparator = (a: VulnerabilityData, b: VulnerabilityData) => {
      let valA, valB;
      if (vulnOrderBy === 'template-id' || vulnOrderBy === 'matched-at') {
        valA = a[vulnOrderBy];
        valB = b[vulnOrderBy];
      }
      else {
        valA = a.info[vulnOrderBy as keyof VulnerabilityData['info']];
        valB = b.info[vulnOrderBy as keyof VulnerabilityData['info']];
      }
      return vulnOrder === 'desc' ? (valA < valB ? 1 : -1) : (valA > valB ? 1 : -1);
    };
    return stableSort(vulnerabilities, comparator);
  }, [vulnerabilities, vulnOrder, vulnOrderBy]);

  const uniquePorts = useMemo(() => {
    const allPorts = ports.map(p => p.portid);
    return [...new Set(allPorts)].sort((a, b) => Number(a) - Number(b));
  }, [ports]);

  const filteredAndSortedPorts = useMemo(() => {
    const filtered = selectedPorts.length === 0 
      ? ports 
      : ports.filter(p => selectedPorts.includes(p.portid));
    return stableSort(filtered, getComparator(portsOrder, portsOrderBy));
  }, [ports, portsOrder, portsOrderBy, selectedPorts]);
  
  useEffect(() => {
    const getScanDetails = async () => {
      if (!scanName) {
        setError('Scan name is missing.');
        setLoading(false);
        return;
      }
      try {
        const [subdomainsData, hostsData, vulnerabilitiesData, osintData, portsData] = await Promise.all([
          fetchSubdomains(scanName),
          fetchHosts(scanName),
          fetchVulnerabilities(scanName),
          fetchOsint(scanName),
          fetchPorts(scanName)
        ]);
        setSubdomains(subdomainsData);
        setHosts(hostsData);
        setVulnerabilities(vulnerabilitiesData);
        setOsint(osintData);
        setPorts(portsData);
      } catch (err) {
        setError('Failed to fetch scan details. Please ensure the backend is running and the scan exists.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    getScanDetails();
  }, [scanName]);

  if (loading) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography variant="h6" sx={{ mt: 2 }}>Loading Scan Details...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="h6" color="error">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Scan Details for: {scanName}
      </Typography>

      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="scan detail tabs">
          <Tab label="Hosts" />
          <Tab label="Subdomains" />
          <Tab label="Vulnerabilities" />
          <Tab label="OSINT" />
          <Tab label="Ports & IPs" />
        </Tabs>
      </Box>

      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" component="h2" gutterBottom>
          Live Hosts ({hosts.length})
        </Typography>
        {hosts.length === 0 ? (
          <Typography variant="body1">No live hosts found for this scan.</Typography>
        ) : (
          <Grid container spacing={3}>
            {hosts.map((host, index) => (
              <Grid item xs={12} sm={6} md={4} key={index} sx={{ display: 'flex' }}>
                <Card sx={{ height: '100%', width: '100%' }}>
                  {host.screenshot && (
                    <CardMedia
                      component="img"
                      height="140"
                      image={`http://localhost:3001${host.screenshot}`}
                      alt={`Screenshot of ${host.url}`}
                    />
                  )}
                  <CardContent>
                    <Typography variant="h6" component="div">
                      <a href={host.url} target="_blank" rel="noopener noreferrer">{host.url}</a>
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Title: {host.title || 'N/A'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Webserver: {host.webserver || 'N/A'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Content Type: {host.content_type || 'N/A'}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Typography variant="h5" component="h2" gutterBottom>
          Subdomains ({subdomains.length})
        </Typography>
        {subdomains.length === 0 ? (
          <Typography variant="body1">No subdomains found for this scan.</Typography>
        ) : (
          <List dense>
            {subdomains.map((sub, index) => (
              <ListItem key={index} component="a" href={`https://${sub}`} target="_blank" rel="noopener noreferrer">
                <ListItemText primary={sub} />
              </ListItem>
            ))}
          </List>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" component="h2" gutterBottom>
          Vulnerabilities ({vulnerabilities.length})
        </Typography>
        {vulnerabilities.length === 0 ? (
          <Typography variant="body1">No vulnerabilities found for this scan.</Typography>
        ) : (
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="vulnerabilities table">
              <TableHead>
                <TableRow>
                  <TableCell sortDirection={vulnOrderBy === 'name' ? vulnOrder : false}>
                    <TableSortLabel
                      active={vulnOrderBy === 'name'}
                      direction={vulnOrderBy === 'name' ? vulnOrder : 'asc'}
                      onClick={() => handleVulnSortRequest('name')}
                    >
                      Name
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={vulnOrderBy === 'severity' ? vulnOrder : false}>
                    <TableSortLabel
                      active={vulnOrderBy === 'severity'}
                      direction={vulnOrderBy === 'severity' ? vulnOrder : 'asc'}
                      onClick={() => handleVulnSortRequest('severity')}
                    >
                      Severity
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={vulnOrderBy === 'matched-at' ? vulnOrder : false}>
                    <TableSortLabel
                      active={vulnOrderBy === 'matched-at'}
                      direction={vulnOrderBy === 'matched-at' ? vulnOrder : 'asc'}
                      onClick={() => handleVulnSortRequest('matched-at')}
                    >
                      Matched At
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={vulnOrderBy === 'template-id' ? vulnOrder : false}>
                    <TableSortLabel
                      active={vulnOrderBy === 'template-id'}
                      direction={vulnOrderBy === 'template-id' ? vulnOrder : 'asc'}
                      onClick={() => handleVulnSortRequest('template-id')}
                    >
                      Template ID
                    </TableSortLabel>
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedVulnerabilities.map((vuln, index) => (
                  <TableRow key={index}>
                    <TableCell component="th" scope="row">
                      {vuln.info.name}
                    </TableCell>
                    <TableCell>{vuln.info.severity}</TableCell>
                    <TableCell>{vuln['matched-at']}</TableCell>
                    <TableCell>{vuln['template-id']}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" component="h2" gutterBottom>
          OSINT
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="h6">Emails ({osint.emails.length})</Typography>
            {osint.emails.length === 0 ? (
              <Typography variant="body1">No emails found.</Typography>
            ) : (
              <List dense>
                {osint.emails.map((email, index) => (
                  <ListItem key={index}>
                    <ListItemText primary={email} />
                  </ListItem>
                ))}
              </List>
            )}
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="h6">Dorks ({osint.dorks.length})</Typography>
            {osint.dorks.length === 0 ? (
              <Typography variant="body1">No dorks found.</Typography>
            ) : (
              <List dense>
                {osint.dorks.map((dork, index) => (
                  <ListItem key={index}>
                    <ListItemText primary={renderDork(dork)} />
                  </ListItem>
                ))}
              </List>
            )}
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        <Box sx={{ mb: 2 }}>
          <Typography variant="h5" component="h2" gutterBottom>
            Ports & IPs ({filteredAndSortedPorts.length})
          </Typography>
          <FormControl sx={{ m: 1, width: 300 }}>
            <InputLabel>Filter by Port</InputLabel>
            <Select
              multiple
              value={selectedPorts}
              onChange={handleSelectedPortsChange}
              input={<OutlinedInput label="Filter by Port" />}
              renderValue={(selected) => (selected as string[]).join(', ')}
            >
              {uniquePorts.map((port) => (
                <MenuItem key={port} value={port}>
                  <Checkbox checked={selectedPorts.indexOf(port) > -1} />
                  <ListItemText primary={port} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
        {ports.length === 0 ? (
          <Typography variant="body1">No port scan data found for this scan.</Typography>
        ) : (
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="ports table">
              <TableHead>
                <TableRow>
                  <TableCell sortDirection={portsOrderBy === 'ip' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'ip'}
                      direction={portsOrderBy === 'ip' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('ip')}
                    >
                      IP Address
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'portid' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'portid'}
                      direction={portsOrderBy === 'portid' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('portid')}
                    >
                      Port
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'protocol' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'protocol'}
                      direction={portsOrderBy === 'protocol' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('protocol')}
                    >
                      Protocol
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'state' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'state'}
                      direction={portsOrderBy === 'state' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('state')}
                    >
                      State
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'service' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'service'}
                      direction={portsOrderBy === 'service' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('service')}
                    >
                      Service
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'product' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'product'}
                      direction={portsOrderBy === 'product' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('product')}
                    >
                      Product
                    </TableSortLabel>
                  </TableCell>
                  <TableCell sortDirection={portsOrderBy === 'version' ? portsOrder : false}>
                    <TableSortLabel
                      active={portsOrderBy === 'version'}
                      direction={portsOrderBy === 'version' ? portsOrder : 'asc'}
                      onClick={() => handlePortsSortRequest('version')}
                    >
                      Version
                    </TableSortLabel>
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredAndSortedPorts.map((port, index) => (
                  <TableRow key={index}>
                    <TableCell>{port.ip}</TableCell>
                    <TableCell>{port.portid}</TableCell>
                    <TableCell>{port.protocol}</TableCell>
                    <TableCell>{port.state}</TableCell>
                    <TableCell>{port.service || 'N/A'}</TableCell>
                    <TableCell>{port.product || 'N/A'}</TableCell>
                    <TableCell>{port.version || 'N/A'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </TabPanel>
    </Box>
  );
}

export default ScanDetail;
