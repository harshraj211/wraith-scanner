import React, { useState } from 'react';
import axios from 'axios';

const EnterpriseSettings = () => {
  const [config, setConfig] = useState({
    jira_url: '', jira_token: '', slack_webhook: '', trivy_path: ''
  });

  const handleSave = async () => {
    // Save to backend /api/v1/settings/integrations
    await axios.post('/api/v1/settings/integrations', config);
    alert('Enterprise integrations saved!');
  };

  return (
    <div className="p-8 bg-gray-900 min-h-screen text-white">
      <h1 className="text-2xl font-bold mb-6">Enterprise Integrations</h1>
      
      <div className="bg-gray-800 p-6 rounded-lg max-w-2xl space-y-4">
        <div>
          <label className="block text-sm mb-1">Jira URL</label>
          <input type="text" value={config.jira_url} onChange={e => setConfig({...config, jira_url: e.target.value})} 
                 className="w-full p-2 bg-gray-700 rounded text-white" />
        </div>
        <div>
          <label className="block text-sm mb-1">Jira API Token</label>
          <input type="password" value={config.jira_token} onChange={e => setConfig({...config, jira_token: e.target.value})} 
                 className="w-full p-2 bg-gray-700 rounded text-white" />
        </div>
        <div>
          <label className="block text-sm mb-1">Slack Webhook URL</label>
          <input type="text" value={config.slack_webhook} onChange={e => setConfig({...config, slack_webhook: e.target.value})} 
                 className="w-full p-2 bg-gray-700 rounded text-white" />
        </div>
        
        <button onClick={handleSave} className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded font-semibold">
          Save Configuration
        </button>
      </div>
    </div>
  );
};

export default EnterpriseSettings;
