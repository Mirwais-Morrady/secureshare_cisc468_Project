package com.cisc468share.storage;

/**
 * Manages persistent contact storage.
 */
public class ContactsStore {
    private String storagePath;
    
    public ContactsStore(String storagePath) {
        this.storagePath = storagePath;
    }
    
    /**
     * Add a contact.
     * 
     * @param contactId The contact identifier
     * @param contactInfo Information about the contact
     */
    public void addContact(String contactId, java.util.Map<String, Object> contactInfo) {
        // TODO: Implement contact addition
    }
    
    /**
     * Get contact information.
     * 
     * @param contactId The contact identifier
     * @return The contact information
     */
    public java.util.Map<String, Object> getContact(String contactId) {
        // TODO: Implement contact retrieval
        return null;
    }
    
    /**
     * List all contacts.
     * 
     * @return List of contact IDs
     */
    public java.util.List<String> listContacts() {
        // TODO: Implement contact listing
        return null;
    }
    
    /**
     * Remove a contact.
     * 
     * @param contactId The contact identifier
     */
    public void removeContact(String contactId) {
        // TODO: Implement contact removal
    }
}
