import React from 'react';import ReactDOM from 'react-dom/client';import { QueryClient, QueryClientProvider } from '@tanstack/react-query';import { BrowserRouter } from 'react-router-dom';import { App } from './app/App';import './styles/index.css';
const client=new QueryClient({defaultOptions:{queries:{retry:1,staleTime:30_000}}});
// 2.8.1: the SPA basename matches Vite's build base so client-side
// routes under `/analyzer/*` resolve against the reverse-proxy prefix
// production uses. `import.meta.env.BASE_URL` is the Vite-provided
// runtime mirror of `vite.config.ts > base` (the leading `/` stays,
// trailing `/` is stripped by react-router).
const basename=(import.meta.env.BASE_URL||'/').replace(/\/$/,'')||undefined;
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><QueryClientProvider client={client}><BrowserRouter basename={basename}><App/></BrowserRouter></QueryClientProvider></React.StrictMode>);
