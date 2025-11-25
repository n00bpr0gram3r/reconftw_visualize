import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Container, Typography, List, ListItem, ListItemText, Box, CircularProgress, AppBar, Toolbar, Button, ThemeProvider, CssBaseline } from '@mui/material';
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
    if (loading) {
      return (
        <Box sx={{ textAlign: 'center', p: 4 }}>
          <CircularProgress />
          <Typography variant="h6" sx={{ mt: 2 }}>Loading Scans...</Typography>
        </Box>
      );
    }

    if (error) {
      return (
        <Box sx={{ textAlign: 'center', p: 4 }}>
          <Typography variant="h6" color="error">{error}</Typography>
        </Box>
      );
    }

    return (
      <Box sx={{ p: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          ReconFTW Visualizer
        </Typography>
        <Typography variant="h5" component="h2" gutterBottom>
          Available Scans
        </Typography>
        {scans.length === 0 ? (
          <Typography variant="body1">No scans found. Please ensure your Recon directory contains scan results.</Typography>
        ) : (
          <List>
            {scans.map((scan) => (
              <ListItem key={scan} button component={Link} to={`/scan/${scan}`}>
                <ListItemText primary={scan} />
              </ListItem>
            ))}
          </List>
        )}
      </Box>
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
