import { v4 as uuidv4 } from 'uuid';
import {
  MemoryEntry,
  MemoryMetadata,
  ConversationEntry,
  Policy,
  Violation,
  Incident
} from '../types/index.js';

/**
 * Simple vector embedding simulation using TF-IDF-like approach
 * In production, use OpenAI embeddings or similar
 */
export class AgentMemory {
  private memoryStore: Map<string, MemoryEntry> = new Map();
  private conversationHistory: ConversationEntry[] = [];
  private readonly MAX_EMBEDDING_DIM = 384;

  /**
   * Simple embedding generation (TF-IDF-like)
   * In production, replace with actual embeddings API
   */
  private generateEmbedding(text: string): number[] {
    const words = text.toLowerCase().split(/\W+/);
    const wordFreq = new Map<string, number>();
    
    // Count word frequencies
    for (const word of words) {
      wordFreq.set(word, (wordFreq.get(word) || 0) + 1);
    }
    
    // Create a simple hash-based embedding
    const embedding = new Array(this.MAX_EMBEDDING_DIM).fill(0);
    
    // Use word hashes to populate embedding
    let idx = 0;
    for (const [word, freq] of wordFreq.entries()) {
      const hash = this.simpleHash(word);
      embedding[hash % this.MAX_EMBEDDING_DIM] += freq;
    }
    
    // Normalize
    const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    if (magnitude > 0) {
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] /= magnitude;
      }
    }
    
    return embedding;
  }

  private simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  /**
   * Store a policy in memory
   */
  storePolicy(policy: Policy): MemoryEntry {
    const content = `
      Policy: ${policy.name}
      Framework: ${policy.framework}
      Description: ${policy.description}
      Requirements: ${policy.requirements.map(r => r.description).join('; ')}
      Controls: ${policy.controls.map(c => c.name).join('; ')}
    `;

    const embedding = this.generateEmbedding(content);
    
    const entry: MemoryEntry = {
      id: uuidv4(),
      type: 'policy',
      content,
      embedding,
      metadata: {
        policyId: policy.id,
        tags: [policy.framework, policy.status, ...policy.metadata.tags],
        source: 'policy-parser'
      },
      createdAt: new Date(),
      accessedAt: new Date(),
      accessCount: 0
    };

    this.memoryStore.set(entry.id, entry);
    return entry;
  }

  /**
   * Store a violation in memory
   */
  storeViolation(violation: Violation): MemoryEntry {
    const content = `
      Violation: ${violation.title}
      Policy: ${violation.policyName}
      Severity: ${violation.severity}
      Status: ${violation.status}
      Asset: ${violation.assetType}: ${violation.assetIdentifier}
      Description: ${violation.description}
    `;

    const embedding = this.generateEmbedding(content);
    
    const entry: MemoryEntry = {
      id: uuidv4(),
      type: 'violation',
      content,
      embedding,
      metadata: {
        violationId: violation.id,
        policyId: violation.policyId,
        tags: [violation.severity, violation.status, violation.assetType],
        source: 'violation-detector'
      },
      createdAt: new Date(),
      accessedAt: new Date(),
      accessCount: 0
    };

    this.memoryStore.set(entry.id, entry);
    return entry;
  }

  /**
   * Store an incident in memory
   */
  storeIncident(incident: Incident): MemoryEntry {
    const content = `
      Incident: ${incident.title}
      Severity: ${incident.severity}
      Status: ${incident.status}
      Priority: ${incident.priority}
      Description: ${incident.description}
      Violations: ${incident.violationIds.join(', ')}
    `;

    const embedding = this.generateEmbedding(content);
    
    const entry: MemoryEntry = {
      id: uuidv4(),
      type: 'incident',
      content,
      embedding,
      metadata: {
        incidentId: incident.id,
        tags: [incident.severity, incident.status, incident.priority],
        source: 'soar-automation'
      },
      createdAt: new Date(),
      accessedAt: new Date(),
      accessCount: 0
    };

    this.memoryStore.set(entry.id, entry);
    return entry;
  }

  /**
   * Store general knowledge in memory
   */
  storeKnowledge(content: string, tags: string[] = [], source: string = 'user'): MemoryEntry {
    const embedding = this.generateEmbedding(content);
    
    const entry: MemoryEntry = {
      id: uuidv4(),
      type: 'knowledge',
      content,
      embedding,
      metadata: {
        tags,
        source
      },
      createdAt: new Date(),
      accessedAt: new Date(),
      accessCount: 0
    };

    this.memoryStore.set(entry.id, entry);
    return entry;
  }

  /**
   * Add a conversation entry
   */
  addConversation(role: 'user' | 'assistant' | 'system', content: string, context: { policies: string[]; violations: string[] } = { policies: [], violations: [] }): ConversationEntry {
    const entry: ConversationEntry = {
      id: uuidv4(),
      role,
      content,
      timestamp: new Date(),
      context
    };

    this.conversationHistory.push(entry);
    
    // Keep only last 100 entries
    if (this.conversationHistory.length > 100) {
      this.conversationHistory = this.conversationHistory.slice(-100);
    }

    return entry;
  }

  /**
   * Search memory by semantic similarity
   */
  search(query: string, limit: number = 5, type?: 'policy' | 'violation' | 'incident' | 'knowledge'): MemoryEntry[] {
    const queryEmbedding = this.generateEmbedding(query);
    
    // Calculate cosine similarity
    const results: { entry: MemoryEntry; score: number }[] = [];
    
    for (const entry of this.memoryStore.values()) {
      if (type && entry.type !== type) continue;
      
      const similarity = this.cosineSimilarity(queryEmbedding, entry.embedding);
      results.push({ entry, score: similarity });
    }
    
    // Sort by similarity and return top results
    results.sort((a, b) => b.score - a.score);
    
    // Update access count and timestamp
    for (const result of results.slice(0, limit)) {
      result.entry.accessedAt = new Date();
      result.entry.accessCount++;
    }
    
    return results.slice(0, limit).map(r => r.entry);
  }

  /**
   * Get relevant context for a query
   */
  getContext(query: string, maxEntries: number = 10): {
    relevantPolicies: MemoryEntry[];
    relevantViolations: MemoryEntry[];
    recentIncidents: MemoryEntry[];
    conversationHistory: ConversationEntry[];
  } {
    const relevantPolicies = this.search(query, maxEntries, 'policy');
    const relevantViolations = this.search(query, maxEntries, 'violation');
    const recentIncidents = Array.from(this.memoryStore.values())
      .filter(e => e.type === 'incident')
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, maxEntries);
    
    const conversationHistory = this.conversationHistory.slice(-20);

    return {
      relevantPolicies,
      relevantViolations,
      recentIncidents,
      conversationHistory
    };
  }

  /**
   * Get all memories by type
   */
  getMemoriesByType(type: 'policy' | 'violation' | 'incident' | 'knowledge'): MemoryEntry[] {
    return Array.from(this.memoryStore.values())
      .filter(e => e.type === type)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Get memory by ID
   */
  getMemory(id: string): MemoryEntry | undefined {
    const entry = this.memoryStore.get(id);
    if (entry) {
      entry.accessedAt = new Date();
      entry.accessCount++;
    }
    return entry;
  }

  /**
   * Delete a memory entry
   */
  deleteMemory(id: string): boolean {
    return this.memoryStore.delete(id);
  }

  /**
   * Clear all memories (use with caution)
   */
  clear(): void {
    this.memoryStore.clear();
    this.conversationHistory = [];
  }

  /**
   * Get memory statistics
   */
  getStats(): {
    totalMemories: number;
    byType: Record<string, number>;
    averageAccessCount: number;
    conversationEntries: number;
  } {
    const memories = Array.from(this.memoryStore.values());
    const byType: Record<string, number> = {};
    
    for (const memory of memories) {
      byType[memory.type] = (byType[memory.type] || 0) + 1;
    }

    const totalAccess = memories.reduce((sum, m) => sum + m.accessCount, 0);
    const avgAccess = memories.length > 0 ? totalAccess / memories.length : 0;

    return {
      totalMemories: memories.length,
      byType,
      averageAccessCount: avgAccess,
      conversationEntries: this.conversationHistory.length
    };
  }

  /**
   * Cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const magA = Math.sqrt(normA);
    const magB = Math.sqrt(normB);
    
    if (magA === 0 || magB === 0) return 0;
    
    return dotProduct / (magA * magB);
  }

  /**
   * Create sample memories for demonstration
   */
  createSampleMemories(): void {
    // Sample policies
    this.storeKnowledge(
      'SOC2 requires annual penetration testing by qualified third party. Testing scope must include all in-scope systems and network infrastructure.',
      ['SOC2', 'penetration-testing', 'annual'],
      'compliance-knowledge'
    );
    
    this.storeKnowledge(
      'ISO 27001 requires documented incident response procedures. All security incidents must be reported within 24 hours.',
      ['ISO27001', 'incident-response', '24h'],
      'compliance-knowledge'
    );
    
    // Sample violations
    this.storeKnowledge(
      'Certificate for api.example.com expires in 15 days - renewal required',
      ['certificate', 'expiry', 'warning'],
      'infrastructure-alert'
    );
    
    this.storeKnowledge(
      'Domain example.com missing SPF record - email spoofing risk',
      ['domain', 'spf', 'security'],
      'infrastructure-alert'
    );
  }
}

export default AgentMemory;
