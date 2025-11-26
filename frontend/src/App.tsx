import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Grid from '@mui/material/Grid';
import {
  Typography,
  Box,
  AppBar,
  Toolbar,
  Button,
  ThemeProvider,
  CssBaseline,
  Container,
  Card,
  CardActionArea,
  CardContent,
  Skeleton,
  Divider,
  Stack,
} from '@mui/material';
import { fetchScans } from './services/api';
import ScanDetail from './pages/ScanDetail'; // Import the new component
import theme from './theme'; // Import the new theme

function App() {
  const [scans, setScans] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const getScans = async () => {
      try {
        const data = await fetchScans();
        setScans(data);
      } catch (err) {
        setError('Failed to fetch scans. Please ensure the backend is running.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    getScans();
  }, []);

  const HomePage = () => {
    if (error) {
      return (
        <Container maxWidth="lg" sx={{ py: 6 }}>
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h6" color="error">{error}</Typography>
          </Box>
        </Container>
      );
    }

    return (
      <Container maxWidth="lg" sx={{ py: 6 }}>
        <Box
          sx={{
            p: { xs: 3, md: 5 },
            background: 'linear-gradient(135deg, rgba(25,118,210,0.1), rgba(25,118,210,0.03))',
            borderRadius: 3,
            border: '1px solid',
            borderColor: 'divider',
            mb: 4,
          }}
        >
          <Stack spacing={2}>
            <Typography variant="h3" component="h1" fontWeight={700}>
              ReconFTW Visualizer
            </Typography>
            <Typography variant="h6" color="text.secondary" maxWidth="md">
              Explore completed ReconFTW runs, review discovered assets, and jump straight into the details that matter.
            </Typography>
            <Divider sx={{ my: 1 }} />
            <Typography variant="subtitle1" color="text.secondary">
              {loading ? 'Loading scans…' : `${scans.length} scan${scans.length === 1 ? '' : 's'} found`}
            </Typography>
          </Stack>
        </Box>

        {loading ? (
          <Grid container spacing={3}>
            {[1, 2, 3].map((placeholder) => (
              <Grid item xs={12} sm={6} md={4} key={placeholder}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Skeleton variant="text" width="60%" sx={{ mb: 1 }} />
                    <Skeleton variant="text" width="80%" />
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        ) : scans.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 6 }}>
            <Typography variant="body1">No scans found. Ensure your Recon directory contains completed scan results.</Typography>
          </Box>
        ) : (
          <Grid container spacing={3}>
            {scans.map((scan) => (
              <Grid item xs={12} sm={6} md={4} key={scan}>
                <Card sx={{ height: '100%' }}>
                  <CardActionArea component={Link} to={`/scan/${scan}`} sx={{ height: '100%' }}>
                    <CardContent>
                      <Typography variant="h6" component="div" gutterBottom>
                        {scan}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Open this scan to view hosts, subdomains, vulnerabilities, OSINT findings, and port data.
                      </Typography>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </Container>
    );
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              <Button color="inherit" component={Link} to="/">ReconFTW Visualizer</Button>
            </Typography>
          </Toolbar>
        </AppBar>
        <main>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan/:scanName" element={<ScanDetail />} />
          </Routes>
        </main>
      </Router>
    </ThemeProvider>
  );
}

export default App;
