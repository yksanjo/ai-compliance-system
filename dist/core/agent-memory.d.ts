import { MemoryEntry, ConversationEntry, Policy, Violation, Incident } from '../types/index.js';
/**
 * Simple vector embedding simulation using TF-IDF-like approach
 * In production, use OpenAI embeddings or similar
 */
export declare class AgentMemory {
    private memoryStore;
    private conversationHistory;
    private readonly MAX_EMBEDDING_DIM;
    /**
     * Simple embedding generation (TF-IDF-like)
     * In production, replace with actual embeddings API
     */
    private generateEmbedding;
    private simpleHash;
    /**
     * Store a policy in memory
     */
    storePolicy(policy: Policy): MemoryEntry;
    /**
     * Store a violation in memory
     */
    storeViolation(violation: Violation): MemoryEntry;
    /**
     * Store an incident in memory
     */
    storeIncident(incident: Incident): MemoryEntry;
    /**
     * Store general knowledge in memory
     */
    storeKnowledge(content: string, tags?: string[], source?: string): MemoryEntry;
    /**
     * Add a conversation entry
     */
    addConversation(role: 'user' | 'assistant' | 'system', content: string, context?: {
        policies: string[];
        violations: string[];
    }): ConversationEntry;
    /**
     * Search memory by semantic similarity
     */
    search(query: string, limit?: number, type?: 'policy' | 'violation' | 'incident' | 'knowledge'): MemoryEntry[];
    /**
     * Get relevant context for a query
     */
    getContext(query: string, maxEntries?: number): {
        relevantPolicies: MemoryEntry[];
        relevantViolations: MemoryEntry[];
        recentIncidents: MemoryEntry[];
        conversationHistory: ConversationEntry[];
    };
    /**
     * Get all memories by type
     */
    getMemoriesByType(type: 'policy' | 'violation' | 'incident' | 'knowledge'): MemoryEntry[];
    /**
     * Get memory by ID
     */
    getMemory(id: string): MemoryEntry | undefined;
    /**
     * Delete a memory entry
     */
    deleteMemory(id: string): boolean;
    /**
     * Clear all memories (use with caution)
     */
    clear(): void;
    /**
     * Get memory statistics
     */
    getStats(): {
        totalMemories: number;
        byType: Record<string, number>;
        averageAccessCount: number;
        conversationEntries: number;
    };
    /**
     * Cosine similarity between two vectors
     */
    private cosineSimilarity;
    /**
     * Create sample memories for demonstration
     */
    createSampleMemories(): void;
}
export default AgentMemory;
//# sourceMappingURL=agent-memory.d.ts.map