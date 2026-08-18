import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DemoSite from "./DemoSite";
import "./index.css";

function Router() {
  const [route, setRoute] = useState(window.location.hash);

  useEffect(() => {
    const onHash = () => setRoute(window.location.hash);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // If hash is #demo, show the standalone demo site
  if (route === "#demo") {
    return <DemoSite />;
  }

  // Otherwise show the main VeilDB dashboard
  return <App />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Router />
  </React.StrictMode>,
);