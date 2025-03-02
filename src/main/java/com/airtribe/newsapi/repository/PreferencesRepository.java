package com.airtribe.newsapi.repository;

import com.airtribe.newsapi.entity.Preferences;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PreferencesRepository extends JpaRepository<Preferences, Long> {
}